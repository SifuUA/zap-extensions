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
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class BusinessUnitContentSecurityPolicyScanner extends PluginPassiveScanner {
    private static final Logger LOG = Logger.getLogger(PluginPassiveScanner.class);

    private static final String MESSAGE_PREFIX = "pscanrules.bucspscanner.";
    private static final int PLUGIN_ID = 10100;
//    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";

    private static final String WILDCARD_URI = "https://*";
    private static final URI PARSED_WILDCARD_URI = URI.parse(WILDCARD_URI);

    private PassiveScanThread parent = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String text1 = "ABCDELMN";
        String text2 = "ABCFGLMN";
        DiffMatchPatch dmp = new DiffMatchPatch();
        LinkedList<DiffMatchPatch.Diff> diff = dmp.diffMain(text1, text2, false);
        System.out.println(diff);

        int startTime = LocalDateTime.now().getSecond();

//        if (LOG.isDebugEnabled()) {
        LOG.debug("Start" + id + " : " + msg.getRequestHeader().getURI().toString());
//        }

        // Only really applies to HTML responses, but also check on Low threshold
        if (isNotHtmlResponse(msg)) {
            return;
        }

        List<String> cspHeaderValues = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_CSP);
        String cspSample = null;

        if (!cspHeaderValues.isEmpty()) {
            String configFile = "C:\\Projects\\zap_plugin\\zap-extensions\\addOns\\pscanrules\\src\\main\\resources\\config\\bu_csp_configuration";

            try {
                String buName = URI.parse(msg.getRequestHeader().getURI().toString()).host;

                BufferedReader reader = new BufferedReader(new FileReader(configFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains(buName)) {
                        cspSample = reader.readLine();
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

            String policyText = cspHeaderValues.toString().replaceAll("[\\[\\]]", "");
            List<String> sampleDirectives = Arrays.asList(Objects.requireNonNull(cspSample).split(";"));
            List<String> readDirectives = Arrays.asList(policyText.split(";"));

            for (int i = 0; i < sampleDirectives.size(); i++) {
                if (sampleDirectives.get(i).equals(readDirectives.get(i))) {
                    System.out.println("BINGO!");
                } else {
                    Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, // PluginID, Risk, Reliability
                            getName());
                    alert.setDetail(
                            getDesc() + getAlertName(sampleDirectives, i),  // Description
                            msg.getRequestHeader().getURI().toString(), // URI
                            "", // Param
                            "", // Attack
                            "other info", // Other info
                            getSolution(), // Solution
                            getReference(), // References
                            "evidence", // Evidence
                            16, // CWE-16: Configuration
                            15, // WASC-15: Application Misconfiguration
                            msg); // HttpMessage
                    parent.raiseAlert(id, alert);
                }
            }
        }
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
