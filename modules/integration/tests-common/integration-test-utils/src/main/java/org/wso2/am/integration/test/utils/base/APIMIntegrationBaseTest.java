/*
*Copyright (c) 2015​, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.am.integration.test.utils.base;

import org.apache.axiom.om.OMElement;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.testng.Assert;
import org.wso2.am.integration.test.utils.APIManagerIntegrationTestException;
import org.wso2.am.integration.test.utils.bean.APIMURLBean;
import org.wso2.am.integration.test.utils.clients.APIPublisherRestClient;
import org.wso2.am.integration.test.utils.clients.APIStoreRestClient;
import org.wso2.am.integration.test.utils.generic.APIMTestCaseUtils;
import org.wso2.carbon.automation.engine.context.AutomationContext;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.engine.context.beans.User;
import org.wso2.carbon.automation.engine.frameworkutils.FrameworkPathUtil;
import org.wso2.carbon.automation.test.utils.http.client.HttpRequestUtil;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;
import org.wso2.carbon.integration.common.utils.LoginLogoutClient;

import javax.xml.stream.XMLStreamException;
import javax.xml.xpath.XPathExpressionException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.regex.Matcher;


/**
 * Base class for all API Manager integration tests
 * Users need to extend this class to write integration tests.
 */
public class APIMIntegrationBaseTest {

    private static final Log log = LogFactory.getLog(APIMIntegrationBaseTest.class);
    protected AutomationContext storeContext, publisherContext, keyManagerContext, gatewayContextMgt, gatewayContextWrk;
    protected OMElement synapseConfiguration;
    protected TestUserMode userMode;
    protected APIMURLBean storeUrls, publisherUrls, gatewayUrlsMgt, gatewayUrlsWrk, keyMangerUrl;
    protected User user;


    /**
     * This method will initialize test environment
     * based on user mode and configuration given at automation.xml
     *
     * @throws APIManagerIntegrationTestException - if test configuration init fails
     */
    protected void init() throws APIManagerIntegrationTestException {
        userMode = TestUserMode.SUPER_TENANT_ADMIN;
        init(userMode);
    }

    /**
     * init the object with user mode , create context objects and get session cookies
     *
     * @param userMode - user mode to run the tests
     * @throws APIManagerIntegrationTestException - if test configuration init fails
     */
    protected void init(TestUserMode userMode) throws APIManagerIntegrationTestException {

        try {
            //create store server instance based on configuration given at automation.xml
            storeContext =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_STORE_INSTANCE, userMode);
            storeUrls = new APIMURLBean(storeContext.getContextUrls());

            //create publisher server instance based on configuration given at automation.xml
            publisherContext =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_PUBLISHER_INSTANCE, userMode);
            publisherUrls = new APIMURLBean(publisherContext.getContextUrls());

            //create gateway server instance based on configuration given at automation.xml
            gatewayContextMgt =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_GATEWAY_MGT_INSTANCE, userMode);
            gatewayUrlsMgt = new APIMURLBean(gatewayContextMgt.getContextUrls());

            gatewayContextWrk =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_GATEWAY_WRK_INSTANCE, userMode);
            gatewayUrlsWrk = new APIMURLBean(gatewayContextWrk.getContextUrls());

            keyManagerContext = new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                                      APIMIntegrationConstants.AM_KEY_MANAGER_INSTANCE, userMode);
            keyMangerUrl = new APIMURLBean(keyManagerContext.getContextUrls());
            user = storeContext.getContextTenant().getContextUser();

        } catch (XPathExpressionException e) {
            log.error("APIM test environment initialization failed", e);
            throw new APIManagerIntegrationTestException("APIM test environment initialization failed", e);
        }

    }

    /**
     * init the object with tenant domain, user key and instance of store,publisher and gateway
     * create context objects and construct URL bean
     *
     * @param domainKey - tenant domain key
     * @param userKey   - tenant user key
     * @throws APIManagerIntegrationTestException - if test configuration init fails
     */
    protected void init(String domainKey, String userKey)
            throws APIManagerIntegrationTestException {

        try {
            //create store server instance based configuration given at automation.xml
            storeContext =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_STORE_INSTANCE, domainKey, userKey);
            storeUrls = new APIMURLBean(storeContext.getContextUrls());

            //create publisher server instance
            publisherContext =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_PUBLISHER_INSTANCE, domainKey, userKey);
            publisherUrls = new APIMURLBean(publisherContext.getContextUrls());

            //create gateway server instance
            gatewayContextMgt =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_GATEWAY_MGT_INSTANCE, domainKey, userKey);
            gatewayUrlsMgt = new APIMURLBean(gatewayContextMgt.getContextUrls());

            gatewayContextWrk =
                    new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                          APIMIntegrationConstants.AM_GATEWAY_WRK_INSTANCE, domainKey, userKey);
            gatewayUrlsWrk = new APIMURLBean(gatewayContextWrk.getContextUrls());

            keyManagerContext = new AutomationContext(APIMIntegrationConstants.AM_PRODUCT_GROUP_NAME,
                                                      APIMIntegrationConstants.AM_KEY_MANAGER_INSTANCE, domainKey, userKey);

            user = storeContext.getContextTenant().getContextUser();

        } catch (XPathExpressionException e) {
            log.error("Init failed", e);
            throw new APIManagerIntegrationTestException("APIM test environment initialization failed", e);
        }

    }

    /**
     * @param relativeFilePath - file path to load config
     * @throws APIManagerIntegrationTestException - Throws if load synapse configuration from file path
     *                                            fails
     */
    protected void loadSynapseConfigurationFromClasspath(String relativeFilePath,
                                                         AutomationContext automationContext,
                                                         String sessionCookie)
            throws APIManagerIntegrationTestException {

        relativeFilePath = relativeFilePath.replaceAll("[\\\\/]", Matcher.quoteReplacement(File.separator));
        OMElement synapseConfig;

        try {
            synapseConfig = APIMTestCaseUtils.loadResource(relativeFilePath);
            updateSynapseConfiguration(synapseConfig, automationContext, sessionCookie);

        } catch (FileNotFoundException e) {
            log.error("synapse config loading issue", e);
            throw new APIManagerIntegrationTestException("synapse config loading issue", e);
        } catch (XMLStreamException e) {
            log.error("synapse config loading issue", e);
            throw new APIManagerIntegrationTestException("synapse config loading issue", e);
        }
    }

    /**
     * @param automationContext - automation context instance of given server
     * @return - created session cookie variable
     * @throws APIManagerIntegrationTestException - Throws if creating session cookie fails
     */
    protected String createSession(AutomationContext automationContext)
            throws APIManagerIntegrationTestException {
        LoginLogoutClient loginLogoutClient;
        try {
            loginLogoutClient = new LoginLogoutClient(automationContext);
            return loginLogoutClient.login();
        } catch (Exception e) {
            log.error("session creation error", e);
            throw new APIManagerIntegrationTestException("session creation error", e);
        }
    }

    /**
     * Get test artifact resources location
     *
     * @return - absolute patch of test artifact directory
     */
    protected String getAMResourceLocation() {
        return FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "AM";
    }

    /**
     * update synapse config to server
     *
     * @param synapseConfig     - config to upload
     * @param automationContext - automation context of the server instance
     * @param sessionCookie     -  logged in session cookie
     * @throws APIManagerIntegrationTestException - If synapse config update fails
     */
    protected void updateSynapseConfiguration(OMElement synapseConfig,
                                              AutomationContext automationContext,
                                              String sessionCookie)
            throws APIManagerIntegrationTestException {

        if (synapseConfiguration == null) {
            synapseConfiguration = synapseConfig;
        } else {
            Iterator<OMElement> itr = synapseConfig.cloneOMElement().getChildElements();  //ToDo
            while (itr.hasNext()) {
                synapseConfiguration.addChild(itr.next());
            }
        }

        try {

            APIMTestCaseUtils.updateSynapseConfiguration(synapseConfig,
                                                         automationContext.getContextUrls().getBackEndUrl(),
                                                         sessionCookie);

        } catch (Exception e) {
            log.error("synapse config  upload error", e);
            throw new APIManagerIntegrationTestException("synapse config  upload error", e);
        }
    }

    protected String getStoreURLHttp() throws XPathExpressionException {
//        return storeContext.getContextUrls().getWebAppURL() + "/";
        return storeUrls.getWebAppURLHttp();
    }

    protected String getStoreURLHttps() throws XPathExpressionException {
        return storeUrls.getWebAppURLHttps();
    }

    protected String getPublisherURLHttp() throws XPathExpressionException {
//        return publisherContext.getContextUrls().getWebAppURL() + "/";
        return publisherUrls.getWebAppURLHttp();
    }

    protected String getPublisherURLHttps() throws XPathExpressionException {
        return publisherUrls.getWebAppURLHttps();
    }

    protected String getGatewayMgtURLHttp() throws XPathExpressionException {
        return gatewayUrlsMgt.getWebAppURLHttp();
    }

    protected String getGatewayMgtBackenURLHttps() throws XPathExpressionException {
        return gatewayUrlsMgt.getWebAppURLHttp();
    }

    protected String getGatewayMgtURLHttps() throws XPathExpressionException {
        return gatewayUrlsMgt.getWebAppURLHttps();
    }

    protected String getGatewayURLHttp() throws XPathExpressionException {
        return gatewayUrlsWrk.getWebAppURLHttp();
    }

    protected String getGatewayURLNhttp() throws XPathExpressionException {
//        return gatewayContext.getContextUrls().getServiceUrl().replace("services", "");
        return gatewayUrlsWrk.getWebAppURLNhttp();
    }

    protected String getKeyManagerURLHttp() throws XPathExpressionException {
        return keyMangerUrl.getWebAppURLHttp();
    }

    protected String getKeyManagerURLHttps() throws XPathExpressionException {
        return keyManagerContext.getContextUrls().getBackEndUrl().replace("/services", "");
    }

    protected String getAPIInvocationURLHttp(String apiContext) throws XPathExpressionException {
        return gatewayContextWrk.getContextUrls().getServiceUrl().replace("/services", "") + "/" + apiContext;
    }

    protected String getAPIInvocationURLHttp(String apiContext, String version)
            throws XPathExpressionException {
        return gatewayContextWrk.getContextUrls().getServiceUrl().replace("/services", "") + "/" + apiContext + "/" + version;
    }

    protected String getAPIInvocationURLHttps(String apiContext) throws XPathExpressionException {
        return gatewayContextWrk.getContextUrls().getSecureServiceUrl() + "/" + apiContext;
    }

    /**
     * Cleaning up the API manager by removing all APIs and applications other than default application
     *
     * @throws APIManagerIntegrationTestException - occurred when calling the apis
     * @throws org.json.JSONException             - occurred when reading the json
     */
    protected void cleanUp() throws Exception {

        APIStoreRestClient apiStore = new APIStoreRestClient(getStoreURLHttp());
        apiStore.login(user.getUserName(), user.getPassword());
        APIPublisherRestClient publisherRestClient = new APIPublisherRestClient(getPublisherURLHttp());
        publisherRestClient.login(user.getUserName(), user.getPassword());
        HttpResponse subscriptionDataResponse = apiStore.getAllSubscriptions();
        verifyResponse(subscriptionDataResponse);
        JSONObject jsonSubscription = new JSONObject(subscriptionDataResponse.getData());

        if (jsonSubscription.getString("error").equals("false")) {
            JSONObject jsonSubscriptionsObject = jsonSubscription.getJSONObject("subscriptions");
            JSONArray jsonApplicationsArray = jsonSubscriptionsObject.getJSONArray("applications");

            //Remove API Subscriptions
            for (int i = 0; i < jsonApplicationsArray.length(); i++) {
                JSONObject appObject = jsonApplicationsArray.getJSONObject(i);
                int id = appObject.getInt("id");
                JSONArray subscribedAPIJSONArray = appObject.getJSONArray("subscriptions");
                for (int j = 0; j < subscribedAPIJSONArray.length(); j++) {
                    JSONObject subscribedAPI = subscribedAPIJSONArray.getJSONObject(j);
                    verifyResponse(apiStore.removeAPISubscription(subscribedAPI.getString("name"), subscribedAPI.getString("version"),
                                                                  subscribedAPI.getString("provider"), String.valueOf(id)));
                }
            }
        }

        //delete all application other than default application
        String applicationData = apiStore.getAllApplications().getData();
        JSONObject jsonApplicationData = new JSONObject(applicationData);
        JSONArray applicationArray = jsonApplicationData.getJSONArray("applications");
        for (int i = 0; i < applicationArray.length(); i++) {
            JSONObject jsonApplication = applicationArray.getJSONObject(i);
            if (!jsonApplication.getString("name").equals("DefaultApplication")) {
                verifyResponse(apiStore.removeApplication(jsonApplication.getString("name")));
            }
        }

        String apiData = apiStore.getAPI().getData();
        JSONObject jsonAPIData = new JSONObject(apiData);
        JSONArray jsonAPIArray = jsonAPIData.getJSONArray("apis");

        //delete all APIs
        for (int i = 0; i < jsonAPIArray.length(); i++) {
            JSONObject api = jsonAPIArray.getJSONObject(i);
            verifyResponse(publisherRestClient.deleteAPI(api.getString("name"), api.getString("version"), user.getUserName()));
        }
    }

    protected void verifyResponse(HttpResponse httpResponse) throws JSONException {
        Assert.assertNotNull(httpResponse, "Response object is null");
        Assert.assertEquals(httpResponse.getResponseCode(), HttpStatus.SC_OK, "Response code is not as expected");
        JSONObject responseData = new JSONObject(httpResponse.getData());
        Assert.assertFalse(responseData.getBoolean("error"), "Error message received " + httpResponse.getData());

    }

    protected void waitForAPIDeploymentSync(String apiProvider, String apiName, String apiVersion,
                                            String expectedResponse)
            throws XPathExpressionException {

        long currentTime = System.currentTimeMillis();
        long waitTime = currentTime + (90 * 1000);

        while (waitTime > System.currentTimeMillis()) {
            HttpResponse response = null;
            try {
                response = HttpRequestUtil.sendGetRequest(getGatewayURLHttp() +
                                                          "APIStatusMonitor/api_status/api-data/" +
                                                          apiProvider + "--" + apiName +
                                                          ":v" + apiVersion, null);
            } catch (IOException ignored) {
                log.warn("WebAPP:" + " APIStatusMonitor not yet deployed or" + " API :" + apiName + " not yet deployed");
            }

            log.info("WAIT for availability of API :" + apiName + " with version: " + apiVersion +
                     " with expected response : " + expectedResponse);

            if (response != null) {
                if (response.getData().contains(expectedResponse)) {
                    log.info("API :" + apiName + " with version: " + apiVersion +
                             " with expected response " + expectedResponse + " found");
                    break;
                } else {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {

                    }
                }
            }
        }
    }

    protected void waitForAPIUnDeploymentSync(String apiProvider, String apiName, String apiVersion,
                                              String expectedResponse)
            throws IOException, XPathExpressionException {

        long currentTime = System.currentTimeMillis();
        long waitTime = currentTime + (90 * 1000);

        while (waitTime > System.currentTimeMillis()) {
            HttpResponse response = HttpRequestUtil.sendGetRequest(getGatewayURLHttp() +
                                                                   "APIStatusMonitor/api_status/api-data/" +
                                                                   apiProvider + "--" + apiName +
                                                                   ":v" + apiVersion, null);

            log.info("WAIT for meta data sync of API :" + apiName + " with version: " + apiVersion +
                     " without entry : " + expectedResponse);

            if (!response.getData().contains(expectedResponse)) {
                log.info("API :" + apiName + " with version: " + apiVersion +
                         " with expected response " + expectedResponse + " not found");
                break;
            } else {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ignored) {

                }
            }
        }
    }

}

