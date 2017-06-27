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

import static org.apache.usergrid.services.ServiceParameter.addParameter;

import java.util.Map;
import java.util.UUID;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.UriInfo;

import org.apache.shiro.subject.Subject;
import org.apache.usergrid.persistence.EntityManager;
import org.apache.usergrid.rest.AbstractContextResource;
import org.apache.usergrid.rest.ApiResponse;
import org.apache.usergrid.rest.RootResource;
import org.apache.usergrid.rest.applications.ServiceResource;
import org.apache.usergrid.security.shiro.utils.SubjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.sun.jersey.api.json.JSONWithPadding;

@Component("org.apache.usergrid.rest.applications.users.BentoboxResources")
@Scope("prototype")
@Produces(MediaType.APPLICATION_JSON)
public class BentoboxResources extends ServiceResource {

	private static final Logger logger = LoggerFactory.getLogger(BentoboxResources.class);

	public BentoboxResources() {
	}

	@Override
	@Path(RootResource.ENTITY_ID_PATH)
	public AbstractContextResource addIdParameter(@Context UriInfo ui, @PathParam("entityId") PathSegment entityId)
			throws Exception {

		logger.info("BentoboxResources.addIdParameter() " + entityId);

		UUID itemId = UUID.fromString(entityId.getPath());
		addParameter(getServiceParameters(), itemId);

		addMatrixParams(getServiceParameters(), ui, entityId);

		return getSubResource(BentoboxResource.class).init(itemId);
	}

	@POST
	@Path("authorize")
	public JSONWithPadding actionAuthorize(@Context UriInfo ui,
			@QueryParam("callback") @DefaultValue("callback") String callback, Map<String, Object> json)
			throws Exception {
		logger.info("BentoboxResources.checkPathPermissions()");
		ApiResponse response = createApiResponse();
		response.setAction("Action authorize");

		EntityManager em = emf.getEntityManager(getApplicationId());
		Subject currentUser = SubjectUtils.getSubject();
		String operation = (String) json.get("operation");
		String path = (String) json.get("path");
		String perm = SubjectUtils.getPermissionFromPath(em.getApplicationRef().getUuid(), operation.toLowerCase(),
				path.toLowerCase());

		boolean permitted = currentUser.isPermitted(perm);

		response.setProperty("permitted", permitted);
		return new JSONWithPadding(response, callback);
	}

	// @Path("{organizationName}")
	// public OrganizationResource
	// getOrganizationByName(@PathParam("organizationName") String
	// organizationName)
	// throws Exception {
	//
	// if ("options".equalsIgnoreCase(request.getMethod())) {
	// throw new NoOpException();
	// }
	//
	// return getSubResource(OrganizationResource.class).init(organizationName);
	// }
}
