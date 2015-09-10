/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.am.integration.test.utils.bean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.am.integration.test.utils.APIManagerIntegrationTestException;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Bean class to contain the Information needed to create and update process of a API.
 */
public class APICreationRequestBean extends AbstractRequest {

    private static final Log log = LogFactory.getLog(APICreationRequestBean.class);
    private String name;
    private String context;
    private JSONObject endpoint;
    private String version;
    private String visibility = "public";
    private String description = "description";
    private String endpointType = "nonsecured";
    private String httpChecked = "http";
    private String httpsChecked = "https";
    private String tags = "tags";
    private String tier = "Silver";
    private String thumbUrl = "";
    private String tiersCollection = "Gold";
    private String resourceCount = "0";
    private String roles = "";
    private String wsdl = "";
    private String defaultVersion = "";
    private String defaultVersionChecked = "";
    private List<APIResourceBean> resourceBeanList;
    private String epUsername = "";
    private String epPassword = "";
    private String sandbox = "";
    private String provider = "admin";
    private String inSequence = "none";
    private String outSequence = "none";
    private String faultSequence = "none";

    /**
     * constructor of the APICreationRequestBean class
     *
     * @param apiName     - Name of the APi
     * @param context     - API context
     * @param version     - API version
     * @param endpointUrl - Endpoint URL of the API
     * @throws APIManagerIntegrationTestException - Exception throws when constructing the end point url JSON
     */
    public APICreationRequestBean(String apiName, String context, String version, String provider, URL endpointUrl)
            throws APIManagerIntegrationTestException {
        this.name = apiName;
        this.context = context;
        this.version = version;
        this.provider = provider;
        resourceBeanList = new ArrayList<APIResourceBean>();
        resourceBeanList.add(new APIResourceBean("GET", "Application & Application User", "Unlimited", "/*"));
        try {
            this.endpoint = new JSONObject("{\"production_endpoints\":{\"url\":\""
                    + endpointUrl + "\",\"config\":null},\"endpoint_type\":\""
                    + endpointUrl.getProtocol() + "\"}");
        } catch (JSONException e) {
            log.error("JSON construct error", e);
            throw new APIManagerIntegrationTestException(" Error When constructing the end point url JSON", e);
        }
    }

    @Override
    public void setAction() {
        setAction("addAPI");
    }

    @Override
    public void setAction(String action) {
        super.setAction(action);
    }


    @Override
    public void init() {

        addParameter("name", name);
        addParameter("context", context);
        addParameter("endpoint_config", endpoint.toString());
        addParameter("provider", provider);
        addParameter("visibility", visibility);
        addParameter("version", version);
        addParameter("description", description);
        addParameter("endpointType", endpointType);
        if (getEndpointType().equals("secured")) {
            addParameter("epUsername", epUsername);
            addParameter("epPassword", epPassword);
        }
        addParameter("http_checked", getHttpChecked());
        addParameter("https_checked", getHttpsChecked());
        addParameter("tags", getTags());
        addParameter("tier", getTier());
        addParameter("thumbUrl", getThumbUrl());
        addParameter("tiersCollection", getTiersCollection());
        //APIM is designed to send 0 as resource count if there is 0 and 1 resources.
        //From 2 resources it sends the correct count.
        if (resourceBeanList.size() < 2) {
            addParameter("resourceCount", "0");
        } else {
            addParameter("resourceCount", resourceBeanList.size() + "");
        }
        if (!(inSequence.equals("none") && outSequence.equals("none") && faultSequence.equals("none"))) {
            addParameter("sequence_check", "on");
        }
        addParameter("inSequence", inSequence);
        addParameter("outSequence", outSequence);
        addParameter("faultSequence", faultSequence);
        int resourceIndex = 0;
        //add resource in formation to the rest parameter list. if only one resource is there
        //parameter name ends  with "-0", more than one parameters are there, we have to add them like,
        //first resource with  parameter ending with "-0", second resource with parameter ending with "-1",
        //third resource with parameter ending with "-2"etc..
        for (APIResourceBean apiResourceBean : resourceBeanList) {
            addParameter("resourceMethod-" + resourceIndex, apiResourceBean.getResourceMethod());
            addParameter("resourceMethodAuthType-" + resourceIndex, apiResourceBean.getResourceMethodAuthType());
            addParameter("resourceMethodThrottlingTier-" + resourceIndex,
                    apiResourceBean.getResourceMethodThrottlingTier());
            addParameter("uriTemplate-" + resourceIndex, apiResourceBean.getUriTemplate());
            resourceIndex++;
        }
        addParameter("default_version", getDefaultVersion());
        addParameter("default_version_checked", getDefaultVersionChecked());
        if (roles.length() > 1) {
            addParameter("roles", getRoles());
        }
        if (wsdl.length() > 1) {
            addParameter("wsdl", getWsdl());
        }
        if (sandbox.length() > 1) {
            addParameter("sandbox", getSandbox());
        }
    }

    public String getEpUsername() {
        return epUsername;
    }

    public void setEpUsername(String epUsername) {
        this.epUsername = epUsername;
    }

    public String getEpPassword() {
        return epPassword;
    }

    public void setEpPassword(String epPassword) {
        this.epPassword = epPassword;
    }

    public List<APIResourceBean> getResourceBeanList() {
        return resourceBeanList;
    }

    public void setResourceBeanList(List<APIResourceBean> resourceBeanList) {
        this.resourceBeanList = resourceBeanList;
    }

    public String getSandbox() {
        return sandbox;
    }

    public void setSandbox(String sandbox) {
        this.sandbox = sandbox;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }

    public String getWsdl() {
        return wsdl;
    }

    public void setWsdl(String wsdl) {
        this.wsdl = wsdl;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getName() {
        return name;
    }

    public JSONObject getEndpointConfig() {
        return endpoint;
    }

    public String getContext() {
        return context;
    }

    public String getVisibility() {
        return visibility;
    }

    public void setVisibility(String visibility) {
        this.visibility = visibility;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getEndpointType() {
        return endpointType;
    }

    public void setEndpointType(String endpointType) {
        this.endpointType = endpointType;
    }

    public String getHttpChecked() {
        return httpChecked;
    }

    public void setHttpChecked(String httpChecked) {
        this.httpChecked = httpChecked;
    }

    public String getHttpsChecked() {
        return httpsChecked;
    }

    public void setHttpsChecked(String httpsChecked) {
        this.httpsChecked = httpsChecked;
    }

    public String getTags() {
        return tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public String getTier() {
        return tier;
    }

    public void setTier(String tier) {
        this.tier = tier;
    }

    public String getThumbUrl() {
        return thumbUrl;
    }

    public void setThumbUrl(String thumbUrl) {
        this.thumbUrl = thumbUrl;
    }

    public String getTiersCollection() {
        return tiersCollection;
    }

    public void setTiersCollection(String tiersCollection) {
        this.tiersCollection = tiersCollection;
    }

    public String getResourceCount() {
        return resourceCount;
    }

    public void setResourceCount(String resourceCount) {
        this.resourceCount = resourceCount;
    }

    public String getDefaultVersion() {
        return defaultVersion;
    }

    public void setDefault_version(String defaultVersion) {
        this.defaultVersion = defaultVersion;
    }

    public String getDefaultVersionChecked() {
        return defaultVersionChecked;
    }

    public void setDefaultVersionChecked(String defaultVersionChecked) {
        this.defaultVersionChecked = defaultVersionChecked;
    }

    public String getInSequence() {
        return inSequence;
    }

    public void setInSequence(String inSequence) {
        this.inSequence = inSequence;
    }

    public String getOutSequence() {
        return outSequence;
    }

    public void setOutSequence(String outSequence) {
        this.outSequence = outSequence;
    }

    public String getFaultSequence() {
        return faultSequence;
    }

    public void setFaultSequence(String faultSequence) {
        this.faultSequence = faultSequence;
    }
}