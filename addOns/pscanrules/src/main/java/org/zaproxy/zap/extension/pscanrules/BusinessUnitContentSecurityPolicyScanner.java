package org.zaproxy.zap.extension.pscanrules;

import com.shapesecurity.salvation.ParserWithLocation;
import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.Origin;
import com.shapesecurity.salvation.data.Policy;
import com.shapesecurity.salvation.data.URI;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BusinessUnitContentSecurityPolicyScanner extends PluginPassiveScanner {
    private static final Logger LOG = Logger.getLogger(PluginPassiveScanner.class);

    private static final String MESSAGE_PREFIX = "pscanrules.changedcspscanner.";
    private static final int PLUGIN_ID = 10100;
//    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";

    private static final String WILDCARD_URI = "https://*";
    private static final URI PARSED_WILDCARD_URI = URI.parse(WILDCARD_URI);

    private PassiveScanThread parent = null;


    private static final String KV_BU = "kruidvat";
    private static final String WTC_BU_UA = "watson.ua";
    private static final String WTC_BU_RU = "watson.ru";
    private static final String MRN_BU = "marionnaud";
    private static final String SD_BU = "superdrug";
    private static final String TPS_BU = "theperfumeshop";
    private static final String IPXL_BU = "iciparisxl";

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        int startTime = LocalDateTime.now().getSecond();
        int noticesRisk = Alert.RISK_INFO;

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
            //implemented bellow
            // checkIfEquals(cspSample, policyText);

            List<String> sampleDirectives = Arrays.asList(cspSample.split(";"));
            List<String> readDirectives = Arrays.asList(policyText.split(";"));

            for (int i = 0; i < sampleDirectives.size(); i++) {
                if (sampleDirectives.get(i).equals(readDirectives.get(i))) {
                    System.out.println("BINGO!");
                } else {
                    Alert alert =
                            new Alert(
                                    getPluginId(),
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM, // PluginID, Risk, Reliability
                                    "AlertName " + i);
                    alert.setDetail(
                            "description", // Description
                            msg.getRequestHeader().getURI().toString(), // URI
                            "param", // Param
                            "attack", // Attack
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

    private boolean isNotHtmlResponse(HttpMessage msg) {
        return (!msg.getResponseHeader().isHtml()
                || HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()))
                && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold());
    }
            /*List<Notice> notices = new ArrayList<>();
            Origin origin = URI.parse(msg.getRequestHeader().getURI().toString());
            Policy policy = ParserWithLocation.parse(policyText, origin, notices);

            if (!notices.isEmpty()) {
                String cspNoticesString = gerCspNoticesString(notices);
                if (cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                        || cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))) {
                    noticesRisk = Alert.RISK_LOW;
                }
                raiseAlert(msg, Constant.messages.getString(MESSAGE_PREFIX + "notices.name"), id, cspNoticesString
                        , getHeaderField(msg, HTTP_HEADER_CSP).get(0), noticesRisk, cspHeaderValues.get(0));
            }

            List<String> allowedWildcardSources = getAllowedWildcardSources(policyText, origin);
            if (!allowedWildcardSources.isEmpty()) {
                String allowedWildcardSrcs =
                        allowedWildcardSources.toString().replace("[", "").replace("]", "");
                String wildcardSrcDesc =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "wildcard.desc", allowedWildcardSrcs);
                raiseAlert(msg, Constant.messages.getString(MESSAGE_PREFIX + "wildcard.name"), id, wildcardSrcDesc,
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0), Alert.RISK_MEDIUM, cspHeaderValues.get(0));
            }

            if (policy.allowsUnsafeInlineScript()) {
                raiseAlert(msg, Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.name"), id,
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.desc"),
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0), Alert.RISK_MEDIUM, cspHeaderValues.get(0));
            }

            if (policy.allowsUnsafeInlineStyle()) {
                raiseAlert(msg, Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"), id,
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.desc"), getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM, cspHeaderValues.get(0));
            }

        } else {
            *//*raiseAlert(
                    msg,
                    Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"),
                    id,
                    Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.desc"),
                    getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                    Alert.RISK_MEDIUM,
                    cspHeaderValues.get(0));*//*
            LOG.debug("CSP do not find!!!");
        }

        LOG.debug("\tScan of record "
                + id
                + " took "
                + (LocalDateTime.now().

                getSecond() - startTime)
                + " seconds");

    }

    private void checkIfEquals(String cspSample, String policyText) {
        List<String> sampleDirectives = Arrays.asList(cspSample.split(";"));
        List<String> readDirectives = Arrays.asList(policyText.split(";"));

        for (int i = 0; i < sampleDirectives.size(); i++) {
            if (sampleDirectives.get(i).equals(readDirectives.get(i))) {
                System.out.println("BINGO!");
            } else {

            }
        }



        *//*
        cspSample = Arrays.stream(line.split(";"))
                .collect(Collectors.toList());*//*
        String[] headerCsp = policyText.split(";");

   *//*     for (int i = 0; i < result.size(); i++) {
//            for (int j = 0; j < result.get(i).size(); j++) {
            if (result.get(i).get(1).equals(headerCsp[i].trim())) {
                System.out.println("BINGO");
            } else {
                System.out.println("NOT!");
                System.out.println("res = " + result.get(i).get(1));
                System.out.println("hed = " + headerCsp[i]);
            }
//            }
        }*//*

    }

    private boolean isNotHtmlResponse(HttpMessage msg) {
        return (!msg.getResponseHeader().isHtml()
                || HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()))
                && !Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold());
    }

    private String gerCspNoticesString(List<Notice> notices) {
        final char NEWLINE = '\n'; //System.lineSeparator();
        StringBuilder stringBuilder = new StringBuilder();

        List<Notice> errorList = Notice.getAllErrors((ArrayList<Notice>) notices);
        if (!errorList.isEmpty()) {
            stringBuilder.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.errors")).append(NEWLINE);
            errorList
                    .forEach(notice -> stringBuilder.append(notice.show()).append(NEWLINE));
        }

        List<Notice> warnList = Notice.getAllWarnings((ArrayList<Notice>) notices);
        if (!warnList.isEmpty()) {
            stringBuilder.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))
                    .append(NEWLINE);
            warnList
                    .forEach(notice -> stringBuilder.append(notice.show()).append(NEWLINE));
        }

        List<Notice> infoList = Notice.getAllInfos((ArrayList<Notice>) notices);
        if (!infoList.isEmpty()) {
            stringBuilder.append(Constant.messages.getString(MESSAGE_PREFIX + "notices.infoItems"))
                    .append(NEWLINE);
            infoList
                    .forEach(notice -> stringBuilder.append(notice.show()).append(NEWLINE));
        }
        return stringBuilder.toString();
    }

    private void raiseAlert(
            HttpMessage msg,
            String name,
            int id,
            String description,
            String param,
            int risk,
            String evidence) {
        String alertName = StringUtils.isEmpty(name) ? getName() : getName() + ": " + name;

        Alert alert =
                new Alert(
                        getPluginId(),
                        risk,
                        Alert.CONFIDENCE_MEDIUM, // PluginID, Risk, Reliability
                        alertName);
        alert.setDetail(
                description, // Description
                msg.getRequestHeader().getURI().toString(), // URI
                param, // Param
                "", // Attack
                "", // Other info
                getSolution(), // Solution
                getReference(), // References
                evidence, // Evidence
                16, // CWE-16: Configuration
                15, // WASC-15: Application Misconfiguration
                msg); // HttpMessage
        parent.raiseAlert(id, alert);
    }

    private List<String> getHeaderField(HttpMessage msg, String header) {
        List<String> matchedHeaders = new ArrayList<>();
        String headers = msg.getResponseHeader().toString();
        String[] headerElements = headers.split("\\r\\n");
        Pattern pattern = Pattern.compile("^" + header, Pattern.CASE_INSENSITIVE);
        for (String hdr : headerElements) {
            Matcher matcher = pattern.matcher(hdr);
            if (matcher.find()) {
                String match = matcher.group();
                matchedHeaders.add(match);
            }
        }
        return matchedHeaders;
    }*/

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    /* private List<String> getAllowedWildcardSources(String policyText, Origin origin) {

         List<String> allowedSources = new ArrayList<String>();
         Policy pol = ParserWithLocation.parse(policyText, origin);

         if (pol.allowsScriptFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("script-src");
             allowedSources.add("script-src-elem");
             allowedSources.add("script-src-attr");
         }
         if (pol.allowsStyleFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("style-src");
             allowedSources.add("style-src-elem");
             allowedSources.add("style-src-attr");
         }
         if (pol.allowsImgFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("img-src");
         }
         if (pol.allowsConnectTo(PARSED_WILDCARD_URI)) {
             allowedSources.add("connect-src");
         }
         if (pol.allowsFrameFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("frame-src");
         }
         if (pol.allowsFrameAncestor(PARSED_WILDCARD_URI)) {
             allowedSources.add("frame-ancestor");
         }
         if (pol.allowsFontFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("font-src");
         }
         if (pol.allowsMediaFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("media-src");
         }
         if (pol.allowsObjectFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("object-src");
         }
         if (pol.allowsManifestFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("manifest-src");
         }
         if (pol.allowsWorkerFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("worker-src");
         }
         if (pol.allowsPrefetchFromSource(PARSED_WILDCARD_URI)) {
             allowedSources.add("prefetch-src");
         }
         return allowedSources;
     }
 */
    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }


}
/*
enum BusinessUnit {
    KV_BU(Set.of("kruidvat", "KV")),
    WTC_BU_UA(Set.of("watsons.ua", "WTC_UA")),
    WTC_BU_RU(Set.of("watsons.ru", "WTC_RU")),
    MRN_BU(Set.of("marionnaud", "MRN")),
    SD_BU(Set.of("superdrug", "SD")),
    TPS_BU(Set.of("theperfumeshop", "TPS")),
    IPXL_BU(Set.of("iciparisxl", "IPXL"));

    final Set<String> bu;

    BusinessUnit(Set<String> bu) {
        this.bu = bu;
    }

    public String getBUName() {
        return bu.
    }

}


enum BU {
    KV_BU,
    WTC_BU_UA,
    WTC_BU_RU,
    MRN_BU,
    SD_BU,
    TPS_BU,
    IPXL_BU;
}*/
