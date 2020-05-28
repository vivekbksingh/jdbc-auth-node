/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.inject.Inject;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that checks credentials against Database
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = JDBCAuthNode.Config.class)
public class JDBCAuthNode extends AbstractDecisionNode {

	public enum ConnectionType {
		JNDI, JDBC;

		private ConnectionType() {
		}
	}

	private final Logger logger = LoggerFactory.getLogger(JDBCAuthNode.class);
	private final Config config;
	private final Realm realm;
	private final static String DEFAULT_TRANSFORM = "org.forgerock.openam.auth.nodes.ClearTextTransform";

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		default ConnectionType connectionType() {
			return ConnectionType.JDBC;
		}

		@Attribute(order = 200, validators = { RequiredValueValidator.class })
		default String jndiName() {
			return "java:comp/env/jdbc/samplePool";
		}

		@Attribute(order = 300, validators = { RequiredValueValidator.class })
		default String jdbcDriver() {
			return "com.mysql.jdbc.Driver";
		}

		@Attribute(order = 400, validators = { RequiredValueValidator.class })
		default String jdbcURL() {
			return "jdbc:mysql://127.0.0.1:3306/test";
		}

		@Attribute(order = 500, validators = { RequiredValueValidator.class })
		default String dbUser() {
			return "root";
		}

		@Attribute(order = 600, validators = { RequiredValueValidator.class })
		@Password
		char[] dbPassword();

		@Attribute(order = 700, validators = { RequiredValueValidator.class })
		default String passwordColumn() {
			return "PASSWORD_COLUMN";
		}

		@Attribute(order = 800, validators = { RequiredValueValidator.class })
		default String preparedStatement() {
			return "select PASSWORD_COLUMN from TABLE where USERNAME_COLUMN = ?";
		}

		@Attribute(order = 900, validators = { RequiredValueValidator.class })
		default String passwordSyntaxTransformClass() {
			return DEFAULT_TRANSFORM;
		}
	}

	/**
	 * Create the node using Guice injection. Just-in-time bindings can be used to
	 * obtain instances of other classes from the plugin.
	 *
	 * @param config
	 *            The service config.
	 * @param realm
	 *            The realm the node is in.
	 * @throws NodeProcessException
	 *             If the configuration was not valid.
	 */
	@Inject
	public JDBCAuthNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
		logger.trace("JDBCAuthNode() : @Inject");
		this.config = config;
		this.realm = realm;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.trace("JDBCAuthNode started");
		Connection database = null;
		PreparedStatement thisStatement = null;
		ResultSet results = null;
		String resultPassword = null;
		String userName = context.sharedState.get(USERNAME).asString();
		String userPassword = context.transientState.get(PASSWORD).asString();
		AMIdentity userIdentity = IdUtils.getIdentity(userName, realm.asDN());
		try {
			if (userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
				try {
					if (config.connectionType().equals(ConnectionType.JNDI)) {
						logger.trace("JDBCAuthNode : Using JNDI Retrieved Connection pool");
						Context initctx = new InitialContext();
						DataSource ds = (DataSource) initctx.lookup(config.jndiName());

						logger.trace("JDBCAuthNode : Datasource Acquired: {}", ds.toString());
						database = ds.getConnection();
					} else {
						logger.trace("JDBCAuthNode : Using Non-persistent JDBC Connection");
						Class.forName(config.jdbcDriver());
						database = DriverManager.getConnection(config.jdbcURL(), config.dbUser(),
								String.valueOf(config.dbPassword()));
					}
					logger.trace("JDBCAuthNode : Connection Acquired: {}", database.toString());
					// Prepare the statement for execution
					logger.trace("JDBCAuthNode : PreparedStatement to build: {} ", config.preparedStatement());
					thisStatement = database.prepareStatement(config.preparedStatement());
					thisStatement.setString(1, userName);
					logger.trace("JDBCAuthNode : Statement to execute: {}", thisStatement);

					// execute the query
					results = thisStatement.executeQuery();

					if (results == null) {
						logger.error("JDBCAuthNode : returned null from executeQuery(). User '{}' not found", userName);
						throw new NodeProcessException("User not found : " + userName);
					}

					// parse the results. should only be one item in one row.
					int index = 0;
					while (results.next()) {
						// do normal processing..its the first and last row
						index++;
						if (index > 1) {
							logger.error("JDBCAuthNode : Too many results. Username should be a primary key");
							throw new NodeProcessException("User not unique : " + userName);
						}
						resultPassword = results.getString(config.passwordColumn());
						if(resultPassword == null) {
							logger.error("JDBCAuthNode : Authentication Failed : Null value received for '{}' column", config.passwordColumn());
							return goTo(false).build();
						}
					}
					if (index == 0) {
						// no results
						logger.error("JDBCAuthNode : No results from your SQL query. User '{}' not found", userName);
						throw new NodeProcessException("User not found : " + userName);
					}
				} catch (Throwable e) {
					logger.error("JDBCAuthNode : JDBC Exception : ", e);
					throw new NodeProcessException("JDBCAuthNode : JDBC Exception : " + e.getMessage());
				} finally {
					// close the resultset
					if (results != null) {
						try {
							results.close();
						} catch (Exception e) {
							// ignore
						}
					}
					// close the statement
					if (thisStatement != null) {
						try {
							thisStatement.close();
						} catch (Exception e) {
							// ignore
						}
					}
					// close the connection when done
					if (database != null) {
						try {
							database.close();
						} catch (Exception dbe) {
							logger.error("Error in closing database connection: {}", dbe.getMessage());
							logger.trace("Fail to close database : ", dbe);
						}
					}
				}

				if (!config.passwordSyntaxTransformClass().equalsIgnoreCase(DEFAULT_TRANSFORM)) {
					try {
						JDBCPasswordSyntaxTransform syntaxTransform = (JDBCPasswordSyntaxTransform) Class
								.forName(config.passwordSyntaxTransformClass()).newInstance();
						logger.trace("Got my Transform Object{}", syntaxTransform.toString());
						userPassword = syntaxTransform.transform(userPassword);

						logger.trace("Password transformed by: {}", config.passwordSyntaxTransformClass());
					} catch (Throwable e) {
						logger.trace("Syntax Transform Exception:{}", e.toString());
						throw new NodeProcessException(e);
					}
				}
				if (userPassword != null && userPassword.equals(resultPassword)) {
					logger.trace("JDBCAuthNode : Authentication Successful");
					return goTo(true).build();
				} else {
					logger.error("Incorrect password. Authentication failed.");
				}
			} else {
				logger.error("JDBCAuthNode : User '{}' not found", userName);
				throw new NodeProcessException("User not found : " + userName);
			}
		} catch (IdRepoException | SSOException e) {
			logger.error("JDBCAuthNode : Error locating user '{}' : {}", userName, e);
			throw new NodeProcessException(e);
		}
		return goTo(false).build();
	}
}
