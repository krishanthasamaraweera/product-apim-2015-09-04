/*
*Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*WSO2 Inc. licenses this file to you under the Apache License,
*Version 2.0 (the "License"); you may not use this file except
*in compliance with the License.
*You may obtain a copy of the License at
*
*http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing,
*software distributed under the License is distributed on an
*"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*KIND, either express or implied.  See the License for the
*specific language governing permissions and limitations
*under the License.
*/

package org.wso2.am.integration.tests.token;

import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.test.utils.base.APIMIntegrationBaseTest;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.bean.*;
import org.wso2.am.integration.test.utils.clients.APIPublisherRestClient;
import org.wso2.am.integration.test.utils.clients.APIStoreRestClient;
import org.wso2.carbon.automation.engine.annotations.ExecutionEnvironment;
import org.wso2.carbon.automation.engine.annotations.SetEnvironment;
import org.wso2.carbon.automation.engine.context.ContextXpathConstants;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.carbon.integration.common.admin.client.TenantManagementServiceClient;
import org.wso2.carbon.integration.common.utils.mgt.ServerConfigurationManager;

import java.io.File;
import java.net.URL;

import static org.testng.Assert.assertNotNull;

/*
 In this test case, It will check refresh token is present in the token response with grant type as password in
 tenant mode.
 */
@SetEnvironment(executionEnvironments = {ExecutionEnvironment.ALL})
public class APIManager3152RefreshTokenTestCase extends APIMIntegrationBaseTest {

    private APIPublisherRestClient apiPublisher;
    private APIStoreRestClient apiStore;
    private ServerConfigurationManager serverConfigurationManager;
    private String userName;
    private String publisherURLHttp;
    private String storeURLHttp;
    private String executionEnvironment;

    @BeforeClass(alwaysRun = true)
    public void deployService() throws Exception {

        super.init();

        executionEnvironment =
                gatewayContextWrk.getConfigurationValue(ContextXpathConstants.EXECUTION_ENVIRONMENT);
        /*
         If test run in external distributed deployment you need to copy following resources accordingly.
         configFiles/hostobjecttest/api-manager.xml
         configFiles/tokenTest/log4j.properties
         */

        publisherURLHttp = getPublisherURLHttp();
        storeURLHttp = getStoreURLHttp();

        userName = user.getUserName();

        if (this.executionEnvironment.equalsIgnoreCase(ExecutionEnvironment.STANDALONE.name())) {

            serverConfigurationManager = new ServerConfigurationManager(gatewayContextWrk);
            serverConfigurationManager.applyConfigurationWithoutRestart(new File(getAMResourceLocation()
                    + File.separator + "configFiles" + File.separator + "tokenTest" + File.separator + "api-manager.xml"));
            serverConfigurationManager.applyConfiguration(new File(getAMResourceLocation()
                    + File.separator + "configFiles" + File.separator + "tokenTest" + File.separator + "log4j.properties"));
        }
        super.init();

        // create a tenant
        TenantManagementServiceClient tenantManagementServiceClient = new TenantManagementServiceClient(
                publisherContext.getContextUrls().getBackEndUrl(), createSession(publisherContext));

        tenantManagementServiceClient.addTenant("11wso2.com",
                publisherContext.getContextTenant().getTenantAdmin().getPassword(),
                publisherContext.getContextTenant().getTenantAdmin().getUserName(), "demo");
        executionEnvironment =
                gatewayContextWrk.getConfigurationValue(ContextXpathConstants.EXECUTION_ENVIRONMENT);
    }

    @Test(groups = "wso2.am", description = "Check whether refresh token issued in tenant mode")
    public void testForRefreshToken() throws Exception {

        String APIName = "TokenRefreshTestAPI";
        String APIContext = "tokenRefreshTestAPI";
        String tags = "youtube, token, media";
        String url = "http://gdata.youtube.com/feeds/api/standardfeeds";
        String description = "This is test API create by API manager integration test";
        String APIVersion = "1.0.0";

        apiPublisher = new APIPublisherRestClient(publisherURLHttp);
        apiStore = new APIStoreRestClient(storeURLHttp);

        apiPublisher.login(userName + "@11wso2.com", userName);

        APIRequest apiRequest = new APIRequest(APIName, APIContext, new URL(url));
        apiRequest.setTags(tags);
        apiRequest.setDescription(description);
        apiRequest.setVersion(APIVersion);
        apiRequest.setSandbox(url);
        apiRequest.setProvider(userName + "@11wso2.com");
        apiPublisher.addAPI(apiRequest);
        APILifeCycleStateRequest updateRequest = new APILifeCycleStateRequest(APIName, userName + "@11wso2.com",
                APILifeCycleState.PUBLISHED);
        apiPublisher.changeAPILifeCycleStatus(updateRequest);

        apiStore.login(userName + "@11wso2.com", storeContext.getContextTenant().getTenantAdmin().getPassword());
        SubscriptionRequest subscriptionRequest = new SubscriptionRequest(APIName, userName + "@11wso2.com");
        subscriptionRequest.setTier("Gold");
        apiStore.subscribe(subscriptionRequest);
        apiStore.addApplication("RefreshTokenTestAPI-Application", "Gold", "", "this-is-test");

        //Generate production token and invoke with that
        APPKeyRequestGenerator generateAppKeyRequest = new APPKeyRequestGenerator("RefreshTokenTestAPI-Application");
        String responseString = apiStore.generateApplicationKey(generateAppKeyRequest).getData();
        JSONObject response = new JSONObject(responseString);

        // get Consumer Key and Consumer Secret
        String consumerKey = response.getJSONObject("data").getJSONObject("key").getString("consumerKey");
        String consumerSecret = response.getJSONObject("data").getJSONObject("key").getString("consumerSecret");

        //Obtain user access token
        String requestBody = "grant_type=password&username=" + userName + "@11wso2.com&password=" +
                storeContext.getContextTenant().getTenantAdmin().getPassword() + "&scope=PRODUCTION";
        URL tokenEndpointURL = new URL(gatewayUrlsWrk.getWebAppURLNhttp() + "token");
        JSONObject accessTokenGenerationResponse = new JSONObject(apiStore.generateUserAccessKey(consumerKey,
                consumerSecret,
                requestBody,
                tokenEndpointURL).getData());

        /*
        Response would be like 
        {"token_type":"bearer","expires_in":3600,"refresh_token":"736b6b5354e4cf24f217718b2f3f72b",
        "access_token":"e06f12e3d6b1367d8471b093162f6729"}
        */

        // get Refresh Token
        assertNotNull(accessTokenGenerationResponse.getString("refresh_token"), "Refresh Token Can Not Be Null");

    }

    @Test(groups = "wso2.am", description = "Check whether refresh token issued in tenant mode")
    public void testForSuperTenantRefreshToken() throws Exception {

        String APIName = "SuperTenantTokenRefreshTestAPI";
        String APIContext = "superTenantTokenRefreshTestAPI";
        String tags = "youtube, token, media";
        String url = "http://gdata.youtube.com/feeds/api/standardfeeds";
        String description = "This is test API create by API manager integration test";
        String APIVersion = "1.0.0";

        userName = storeContext.getSuperTenant().getTenantAdmin().getUserName();
        apiPublisher = new APIPublisherRestClient(publisherURLHttp);
        apiStore = new APIStoreRestClient(storeURLHttp);

        apiPublisher.login(userName, storeContext.getSuperTenant().getTenantAdmin().getPassword());

        APIRequest apiRequest = new APIRequest(APIName, APIContext, new URL(url));
        apiRequest.setTags(tags);
        apiRequest.setDescription(description);
        apiRequest.setVersion(APIVersion);
        apiRequest.setSandbox(url);
        apiPublisher.addAPI(apiRequest);
        APILifeCycleStateRequest updateRequest = new APILifeCycleStateRequest(APIName, userName,
                APILifeCycleState.PUBLISHED);
        apiPublisher.changeAPILifeCycleStatus(updateRequest);

        apiStore.login(userName, storeContext.getContextTenant().getTenantAdmin().getPassword());
        SubscriptionRequest subscriptionRequest = new SubscriptionRequest(APIName, userName);
        subscriptionRequest.setTier("Gold");
        apiStore.subscribe(subscriptionRequest);
        apiStore.addApplication("RefreshTokenTestAPI-Application", "Gold", "", "this-is-test");

        //Generate production token and invoke with that
        APPKeyRequestGenerator generateAppKeyRequest = new APPKeyRequestGenerator("RefreshTokenTestAPI-Application");
        String responseString = apiStore.generateApplicationKey(generateAppKeyRequest).getData();
        JSONObject response = new JSONObject(responseString);

        // get Consumer Key and Consumer Secret
        String consumerKey = response.getJSONObject("data").getJSONObject("key").getString("consumerKey");
        String consumerSecret = response.getJSONObject("data").getJSONObject("key").getString("consumerSecret");

        //Obtain user access token
        waitForAPIDeploymentSync(apiRequest.getProvider(), apiRequest.getName(), apiRequest.getVersion(),
                APIMIntegrationConstants.IS_API_EXISTS);

        String requestBody = "grant_type=password&username=" + userName + "&password=" +
                storeContext.getContextTenant().getTenantAdmin().getPassword() + "&scope=PRODUCTION";
        URL tokenEndpointURL = new URL(getAPIInvocationURLHttp("token"));
        JSONObject accessTokenGenerationResponse = new JSONObject(apiStore.generateUserAccessKey(consumerKey,
                consumerSecret,
                requestBody,
                tokenEndpointURL).getData());

        assertNotNull(accessTokenGenerationResponse.getString("refresh_token"), "Refresh Token Can Not Be Null");
    }

    @AfterClass(alwaysRun = true)
    public void unDeployService() throws Exception {

        cleanUp("11wso2.com", "admin", "admin");
        super.cleanUp();
        if (this.executionEnvironment.equalsIgnoreCase(ExecutionEnvironment.STANDALONE.name())) {
            serverConfigurationManager.restoreToLastConfiguration();
        }
    }

    /*  Removing API subscription, application and API of the tenant 11wso2.com*/
    protected void cleanUp(String tenantDomain, String userName, String password) throws Exception {
        APIStoreRestClient apiStore = new APIStoreRestClient(this.getStoreURLHttp());
        apiStore.login(userName + "@" + tenantDomain, password);
        APIPublisherRestClient publisherRestClient = new APIPublisherRestClient(this.getPublisherURLHttp());
        publisherRestClient.login(userName + "@" + tenantDomain, password);
        HttpResponse subscriptionDataResponse = apiStore.getAllSubscriptions();
        this.verifyResponse(subscriptionDataResponse);
        JSONObject jsonSubscription = new JSONObject(subscriptionDataResponse.getData());
        JSONArray jsonAPIArray;
        int i;
        JSONObject api;
        if (jsonSubscription.getString("error").equals("false")) {
            JSONObject applicationData = jsonSubscription.getJSONObject("subscriptions");
            JSONArray jsonApplicationData = applicationData.getJSONArray("applications");

            for (int applicationArray = 0; applicationArray < jsonApplicationData.length(); ++applicationArray) {
                JSONObject apiData = jsonApplicationData.getJSONObject(applicationArray);
                int jsonAPIData = apiData.getInt("id");
                jsonAPIArray = apiData.getJSONArray("subscriptions");

                for (i = 0; i < jsonAPIArray.length(); ++i) {
                    api = jsonAPIArray.getJSONObject(i);
                    this.verifyResponse(apiStore.removeAPISubscription(api.getString("name"), api.getString("version"),
                            api.getString("provider"), String.valueOf(jsonAPIData)));
                }
            }
        }

        String var13 = apiStore.getAllApplications().getData();
        JSONObject var14 = new JSONObject(var13);
        JSONArray var15 = var14.getJSONArray("applications");

        JSONObject var17;
        for (int var16 = 0; var16 < var15.length(); ++var16) {
            var17 = var15.getJSONObject(var16);
            if (!var17.getString("name").equals("DefaultApplication")) {
                this.verifyResponse(apiStore.removeApplication(var17.getString("name")));
            }
        }

        String var18 = apiStore.getAPI().getData();
        var17 = new JSONObject(var18);
        jsonAPIArray = var17.getJSONArray("apis");

        for (i = 0; i < jsonAPIArray.length(); ++i) {
            api = jsonAPIArray.getJSONObject(i);
            this.verifyResponse(publisherRestClient.deleteAPI(api.getString("name"), api.getString("version"), userName + "@" + tenantDomain));
        }
    }
}
