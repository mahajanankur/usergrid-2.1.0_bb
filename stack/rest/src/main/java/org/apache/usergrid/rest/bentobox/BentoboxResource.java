/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.usergrid.rest.bentobox;

import java.util.Set;
import java.util.UUID;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;

import org.apache.usergrid.rest.ApiResponse;
import org.apache.usergrid.rest.applications.ServiceResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.sun.jersey.api.json.JSONWithPadding;

@Component("org.apache.usergrid.rest.applications.users.BentoboxResource")
@Scope("prototype")
@Produces(MediaType.APPLICATION_JSON)
public class BentoboxResource extends ServiceResource {

	private static final Logger logger = LoggerFactory.getLogger(BentoboxResource.class);

	UUID userId;

	public BentoboxResource() {
	}

	public BentoboxResource init(UUID userId) throws Exception {
		this.userId = userId;
		return this;
	}

	@GET
	@Path("roles")
	public JSONWithPadding getUsersRoles(@Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback) throws Exception {
		logger.info("BentoboxResource.getUsersRoles()");
		ApiResponse response = createApiResponse();
		response.setAction("User Roles");

		UUID applicationId = getApplicationId();
		Set<String> userRoles = emf.getEntityManager(applicationId).getUserRoles(userId);
		response.setProperty("roles", userRoles);
		return new JSONWithPadding(response, callback);
	}
	//
	// @POST
	// @Path("permissions")
	// public JSONWithPadding assignUserPermissions(@Context UriInfo ui,
	// @QueryParam("callback") @DefaultValue("callback") String callback) throws
	// Exception {
	// logger.info("BentoboxResource.assignUserPermissions()");
	// ApiResponse response = createApiResponse();
	// response.setAction("Assign User Permissions");
	// String permission = "get,post,put:/users/" + userId;
	// UUID applicationId = getApplicationId();
	// emf.getEntityManager(applicationId).grantUserPermission(userId,
	// permission);
	// response.setProperty("permissions", permission);
	// return new JSONWithPadding(response, callback);
	// }

}
