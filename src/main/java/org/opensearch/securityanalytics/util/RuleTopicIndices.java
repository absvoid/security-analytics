/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;

public class RuleTopicIndices {
    private static final Logger log = LogManager.getLogger(DetectorIndices.class);

    private final Client client;

    private final ClusterService clusterService;
    private final LogTypeService logTypeService;

    public RuleTopicIndices(Client client, ClusterService clusterService, LogTypeService logTypeService) {
        this.client = client;
        this.clusterService = clusterService;
        this.logTypeService = logTypeService;
    }

    public static String ruleTopicIndexSettings() throws IOException {
        return new String(Objects.requireNonNull(DetectorIndices.class.getClassLoader().getResourceAsStream("mappings/detector-settings.json")).readAllBytes(), Charset.defaultCharset());
    }

    public void initRuleTopicIndexTemplate(ActionListener<AcknowledgedResponse> actionListener) throws IOException {
        if (!ruleTopicIndexTemplateExists()) {
            getAllRuleIndices(ActionListener.wrap(allRuleIndices -> {
                // Compose list of all patterns to cover all query indices
                List<String> indexPatterns = new ArrayList<>();
                for(String ruleIndex : allRuleIndices) {
                    indexPatterns.add(ruleIndex + "*");
                }

                ComposableIndexTemplate template = new ComposableIndexTemplate(
                        indexPatterns,
                        new Template(
                                Settings.builder().loadFromSource(ruleTopicIndexSettings(), XContentType.JSON).build(),
                                null,
                                null
                        ),
                        null,
                        500L,
                        null,
                        null
                );

                client.execute(
                        PutComposableIndexTemplateAction.INSTANCE,
                        new PutComposableIndexTemplateAction.Request(DetectorMonitorConfig.OPENSEARCH_SAP_RULE_INDEX_TEMPLATE)
                                .indexTemplate(template)
                                .create(true),
                        actionListener
                );

            }, actionListener::onFailure));
        } else {
            actionListener.onResponse(new AcknowledgedResponse(true));
        }
    }

    public boolean ruleTopicIndexTemplateExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.metadata().templatesV2()
                .get(DetectorMonitorConfig.OPENSEARCH_SAP_RULE_INDEX_TEMPLATE) != null;
    }

    private void getAllRuleIndices(ActionListener<List<String>> listener) {

        logTypeService.getAllLogTypes(ActionListener.wrap(logTypes -> {
            listener.onResponse(
                    logTypes
                        .stream()
                        .map(logType -> DetectorMonitorConfig.getRuleIndex(logType))
                        .collect(Collectors.toList())
            );
        }, listener::onFailure));
    }
}