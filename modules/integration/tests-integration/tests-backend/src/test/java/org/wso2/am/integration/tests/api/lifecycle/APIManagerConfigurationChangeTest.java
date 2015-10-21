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

package org.wso2.am.integration.tests.api.lifecycle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.wso2.am.admin.clients.webapp.WebAppAdminClient;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.webapp.WebAppDeploymentUtil;
import org.wso2.carbon.automation.engine.annotations.ExecutionEnvironment;
import org.wso2.carbon.automation.engine.annotations.SetEnvironment;
import org.wso2.carbon.automation.test.utils.common.FileManager;
import org.wso2.carbon.automation.test.utils.common.TestConfigurationProvider;
import org.wso2.carbon.integration.common.utils.mgt.ServerConfigurationManager;

import java.io.File;

/**
 * Deploy jaxrs_basic webApp and monitoring webApp required to run tests
 * jaxrs_basic - Provides rest backend to run tests
 * APIStatusMonitor - Can be used to retrieve API deployment status in worker and manager nodes
 */
public class APIManagerConfigurationChangeTest extends APIManagerLifecycleBaseTest {

    private static final Log log = LogFactory.getLog(APIManagerConfigurationChangeTest.class);
    private final String WEB_APP_NAME = "jaxrs_basic";
    private final String WEB_APP_FILE_NAME = "jaxrs_basic.war";
    private String sessionId;
    private WebAppAdminClient webAppAdminClient;


    @BeforeTest(alwaysRun = true)
    public void startChangeAPIMConfigureXml() throws Exception {
        super.init();

        String sourcePath =
                TestConfigurationProvider.getResourceLocation() + File.separator + "artifacts" +
                File.separator + "AM" + File.separator + "lifecycletest" + File.separator +
                WEB_APP_FILE_NAME;

        String pathAPIStatusMonitorWar =
                TestConfigurationProvider.getResourceLocation() + File.separator + "artifacts" +
                File.separator + "AM" + File.separator + "war" + File.separator +
                APIMIntegrationConstants.AM_MONITORING_WEB_APP_NAME + ".war";

        sessionId = createSession(gatewayContextMgt);

        WebAppAdminClient webAppAdminClient = new WebAppAdminClient(
                gatewayContextMgt.getContextUrls().getBackEndUrl(), sessionId);

        webAppAdminClient.uploadWarFile(sourcePath);
        webAppAdminClient.uploadWarFile(pathAPIStatusMonitorWar);

        WebAppDeploymentUtil.isWebApplicationDeployed(gatewayContextMgt.getContextUrls().getBackEndUrl(),
                                                      sessionId, WEB_APP_NAME);

        WebAppDeploymentUtil.isWebApplicationDeployed(gatewayContextMgt.getContextUrls().getBackEndUrl(),
                                                      sessionId, APIMIntegrationConstants.AM_MONITORING_WEB_APP_NAME);

        WebAppDeploymentUtil.isMonitoringAppDeployed(gatewayContextWrk.getContextUrls().getWebAppURL());

    }

    //@AfterTest(alwaysRun = true)
    public void startRestoreAPIMConfigureXml() throws Exception {
        //TODO remove webAPPS
    }
}
