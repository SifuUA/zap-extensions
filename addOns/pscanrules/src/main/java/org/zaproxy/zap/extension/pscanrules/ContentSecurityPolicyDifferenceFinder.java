package org.zaproxy.zap.extension.pscanrules;

import com.shapesecurity.salvation.data.URI;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.bitbucket.cowwoc.diffmatchpatch.DiffMatchPatch;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class ContentSecurityPolicyDifferenceFinder extends PluginPassiveScanner {
    private static final Logger LOG = Logger.getLogger(ContentSecurityPolicyDifferenceFinder.class);

    private static final int PLUGIN_ID = 10100;
    private static final String MESSAGE_PREFIX = "pscanrules.cspdifferencefinder.";
    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";

    private PassiveScanThread parent = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (LOG.isDebugEnabled()) {
            LOG.info("Start of scanning" + id + " : " + msg.getRequestHeader().getURI().toString());
        }

        if (isNotHtmlResponse(msg)) {
            return;
        }
        List<String> cspHeaderValues = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_CSP);

        if (!cspHeaderValues.isEmpty()) {
            String cspSample = getCSPFromConfig(msg);
            String policyText = cspHeaderValues.toString().replaceAll("[\\[\\]]", "");

            List<String> sampleDirectives = Arrays.stream(Objects.requireNonNull(cspSample).split(";"))
                    .map(String::trim)
                    .collect(Collectors.toList());
            List<String> readDirectives = Arrays.stream(policyText.split(";"))
                    .map(String::trim)
                    .collect(Collectors.toList());
            compareCSP(msg, id, sampleDirectives, readDirectives, cspHeaderValues);
        }
    }

    private void compareCSP(HttpMessage msg, int id, List<String> sampleDirectives, List<String> siteDirectives, List<String> cspHeaderValues) {
        for (int i = 0; i < sampleDirectives.size(); i++) {
            if (sampleDirectives.get(i).equals(siteDirectives.get(i))) {
                LOG.info(getName() + getDirectiveName(sampleDirectives, i) + " is matches the pattern");
            } else {
                AlertDto alertDto = new AlertDto.Builder()
                        .withMsg(msg)
                        .withId(id)
                        .withName(getName() + " " + getDirectiveName(sampleDirectives, i))
                        .withDescription(getDifferencesDetails(sampleDirectives, siteDirectives, i))
                        .withEvidence(cspHeaderValues.get(0))
                        .withDifference(getDesc() + getAlertName(sampleDirectives, i))
                        .build();
                raiseAlert(alertDto);
            }
        }
        if (sampleDirectives.size() > siteDirectives.size()) {
            raiseNewDirectiveAlert(msg, id, siteDirectives, sampleDirectives, cspHeaderValues);
        } else if (siteDirectives.size() > sampleDirectives.size()) {
            raiseNewDirectiveAlert(msg, id, sampleDirectives, siteDirectives, cspHeaderValues);
        }
    }

    private void raiseNewDirectiveAlert(HttpMessage msg, int id, List<String> sampleDirectives, List<String> siteDirectives, List<String> cspHeaderValues) {
        int difference = siteDirectives.size() - sampleDirectives.size();
        for (int i = 0; i < difference; i++) {
            AlertDto alertDto = new AlertDto.Builder()
                    .withMsg(msg)
                    .withId(id)
                    .withName(getName() + getDirectiveName(siteDirectives, siteDirectives.size() - i - 1))
                    .withDescription(getDesc() + getAlertName(siteDirectives, siteDirectives.size() - i - 1))
                    .withEvidence(cspHeaderValues.get(0))
                    .withDifference("Detected new CSP directive - " + siteDirectives.get(siteDirectives.size() - i - 1))
                    .build();
            raiseAlert(alertDto);
        }
    }

    private void raiseAlert(AlertDto alertDto) {
        Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, alertDto.getAlertName());
        alert.setDetail(
                alertDto.getAlertDescription(),  // Description
                alertDto.getMsg().getRequestHeader().getURI().toString(), // URI
                getName(), // Param
                "", // Attack
                alertDto.getDifference(), // Other info
                getSolution(), // Solution
                getReference(), // References
                alertDto.getEvidence(), // Evidence
                16, // CWE-16: Configuration
                15, // WASC-15: Application Misconfiguration
                alertDto.getMsg()); // HttpMessage
        parent.raiseAlert(alertDto.getMsgId(), alert);
        if (LOG.isDebugEnabled()) {
            LOG.info("Alert raised with information" + alert.toString());
        }
    }

    private String getCSPFromConfig(HttpMessage msg) {
        String cspSample = null;
        try {
            String line;
            String siteName = URI.parse(msg.getRequestHeader().getURI().toString()).host;
            BufferedReader reader = new BufferedReader(new FileReader(getConfigFile()));

            while ((line = reader.readLine()) != null) {
                if (line.contains(siteName)) {
                    cspSample = reader.readLine();
                    break;
                }
            }
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Error while read config file" + e);
            }
        }
        return cspSample;
    }

    private String getDirectiveName(List<String> sampleDirectives, int i) {
        return Arrays.stream(sampleDirectives.get(i).trim().split(" ")).findFirst().get();
    }

    private String getDifferencesDetails(List<String> sampleDirectives, List<String> readDirectives, int i) {
        LinkedList<String> result = new LinkedList<>();
        DiffMatchPatch diffMatchPatch = new DiffMatchPatch();
        LinkedList<DiffMatchPatch.Diff> listOfDiff = diffMatchPatch.diffMain(sampleDirectives.get(i), readDirectives.get(i), false);

        for (DiffMatchPatch.Diff node : listOfDiff) {
            if (node.operation.name().equals("INSERT")) {
                result.push("The following part is new CSP directives: " + node.text + "\n" + "\n");
            } else if (node.operation.name().equals("EQUAL")) {
                result.add("The following part is equal in site_csp_configuration file and CSP from site: " + node.text + "\n");
            } else {
                result.add("The following part with new directive or some of directive has been modified: " + node.text + "\n");
            }
        }
        return result.toString().replaceAll("[\\[\\]]", " ");
    }

    private String getAlertName(List<String> sampleDirectives, int i) {
        return sampleDirectives.get(i).split(" ")[0];
    }

    private boolean isNotHtmlResponse(HttpMessage msg) {
        return (!msg.getResponseHeader().isHtml()
                && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold()));
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
        return Constant.messages.getString(MESSAGE_PREFIX + "description");
    }

    private String getSolution() {
            return Constant.messages.getString(MESSAGE_PREFIX + "solution");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "reference");
    }

    private File getConfigFile() {
        return new File("C:\\Users\\Oleksii_Kres\\Idea Project\\zap_project\\zap-extensions\\addOns\\pscanrules\\src\\main\\zapHomeFiles\\site_config\\site_csp_configuration");
//        return new File(Constant.getZapHome() + File.separator + "site_config" + File.separator + "site_csp_configuration");
    }
}

class AlertDto {
    private HttpMessage msg;
    private int msgId;
    private String alertName;
    private String alertDescription;
    private String evidence;
    private String difference;

    public HttpMessage getMsg() {
        return msg;
    }

    public int getMsgId() {
        return msgId;
    }

    public String getAlertName() {
        return alertName;
    }

    public String getAlertDescription() {
        return alertDescription;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getDifference() {
        return difference;
    }

    public static class Builder {
        private final AlertDto alertDto;

        public Builder() {
            alertDto = new AlertDto();
        }

        public Builder withMsg(HttpMessage msg) {
            alertDto.msg = msg;
            return this;
        }

        public Builder withId(int id) {
            alertDto.msgId = id;
            return this;
        }

        public Builder withName(String name) {
            alertDto.alertName = name;
            return this;
        }

        public Builder withDescription(String description) {
            alertDto.alertDescription = description;
            return this;
        }

        public Builder withEvidence(String evidence) {
            alertDto.evidence = evidence;
            return this;
        }

        public Builder withDifference(String difference) {
            alertDto.difference = difference;
            return this;
        }

        public AlertDto build() {
            return alertDto;
        }
    }
}
