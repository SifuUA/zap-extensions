package org.zaproxy.zap.extension.pscanrules;

import com.shapesecurity.salvation.data.URI;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.bitbucket.cowwoc.diffmatchpatch.DiffMatchPatch;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class BusinessUnitContentSecurityPolicyScanner extends PluginPassiveScanner {
    private static final Logger LOG = Logger.getLogger(PluginPassiveScanner.class);

    private static final int PLUGIN_ID = 10100;
    private static final String MESSAGE_PREFIX = "pscanrules.bucspscanner.";
    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";
    String configFilePath = "C:\\Projects\\zap_plugin\\zap-extensions\\addOns\\pscanrules\\src\\main\\resources\\config\\bu_csp_configuration";

    private PassiveScanThread parent = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
//        if (LOG.isDebugEnabled()) {
        LOG.info("Start of scanning" + id + " : " + msg.getRequestHeader().getURI().toString());
//        }

        // Only really applies to HTML responses, but also check on Low threshold
        if (isNotHtmlResponse(msg)) {
            return;
        }
        List<String> cspHeaderValues = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_CSP);

        if (!cspHeaderValues.isEmpty()) {
            String cspSample = getCSPFromConfig(msg);
            String policyText = cspHeaderValues.toString().replaceAll("[\\[\\]]", "");
            List<String> sampleDirectives = Arrays.asList(Objects.requireNonNull(cspSample).split(";"));
            List<String> readDirectives = Arrays.asList(policyText.split(";"));

            compareCSP(msg, id, sampleDirectives, readDirectives);
        }
    }

    private void compareCSP(HttpMessage msg, int id, List<String> sampleDirectives, List<String> readDirectives) {
        for (int i = 0; i < sampleDirectives.size(); i++) {
            if (sampleDirectives.get(i).equals(readDirectives.get(i))) {
                LOG.info(getName() + getDirectiveName(sampleDirectives, i) + " is matches the pattern");
            } else {
                raiseAlert(msg, id, sampleDirectives, readDirectives, i);
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, List<String> sampleDirectives, List<String> readDirectives, int i) {
        Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, // PluginID, Risk, Reliability
                getName() + getDirectiveName(sampleDirectives, i));
        alert.setDetail(
                getDesc() + getAlertName(sampleDirectives, i),  // Description
                msg.getRequestHeader().getURI().toString(), // URI
                "", // Param
                "", // Attack
                getDifferencesDetails(sampleDirectives, readDirectives, i), // Other info
                getSolution(), // Solution
                getReference(), // References
                "evidence", // Evidence
                16, // CWE-16: Configuration
                15, // WASC-15: Application Misconfiguration
                msg); // HttpMessage
        parent.raiseAlert(id, alert);
    }

    private String getCSPFromConfig(HttpMessage msg) {
        String cspSample = null;
        try {
            String buName = URI.parse(msg.getRequestHeader().getURI().toString()).host;
            BufferedReader reader = new BufferedReader(new FileReader(configFilePath));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(buName)) {
                    cspSample = reader.readLine();
                    break;
                }
            }
        } catch (IOException e) {
            LOG.error(e);
        }
        return cspSample;
    }

    private String getDirectiveName(List<String> sampleDirectives, int i) {
        return Arrays.stream(sampleDirectives.get(i).trim().split(" ")).findFirst().get();
    }

    private String getDifferencesDetails(List<String> sampleDirectives, List<String> readDirectives, int i) {
        StringBuilder sb = new StringBuilder();
        DiffMatchPatch diffMatchPatch = new DiffMatchPatch();
        LinkedList<DiffMatchPatch.Diff> listOfDiff = diffMatchPatch.diffMain(sampleDirectives.get(i), readDirectives.get(i), false);

        for (DiffMatchPatch.Diff node : listOfDiff) {
            if (node.operation.name().equals("EQUAL")) {
                sb.append("This is part is equal: ").append(node.text).append("\n");
            } else if (node.operation.name().equals("INSERT")) {
                sb.append("This is part was defined in configuration file: ").append(node.text).append("\n");
            } else {//DELETE
                sb.append("This is a new directive or some of directive has been modified: ").append(node.text).append("\n");
            }
        }
        return sb.toString();
    }

    private String getAlertName(List<String> sampleDirectives, int i) {
        return sampleDirectives.get(i).split(" ")[0];
    }

    private boolean isNotHtmlResponse(HttpMessage msg) {
        return (!msg.getResponseHeader().isHtml()
                || HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()))
                && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDesc() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }


    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
}
