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

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BusinessUnitContentSecurityPolicyScanner extends PluginPassiveScanner {
    private static final Logger LOG = Logger.getLogger(PluginPassiveScanner.class);

    private static final String MESSAGE_PREFIX = "pscanrules.changedcspscanner.";
    private static final int PLUGIN_ID = 10100;
//    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";

    private static final String WILDCARD_URI = "http://*";
    private static final URI PARSED_WILDCARD_URI = URI.parse(WILDCARD_URI);

    private PassiveScanThread parent = null;

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

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        int startTime = LocalDateTime.now().getSecond();
        int noticesRisk = Alert.RISK_INFO;
        boolean cspHeaderExists = false;

//        if (LOG.isDebugEnabled()) {
        LOG.debug("Start" + id + " : " + msg.getRequestHeader().getURI().toString());
//        }

        // Only really applies to HTML responses, but also check on Low threshold
        if (isNotHtmlResponse(msg)) {
            return;
        }

        List<String> cspHeaderValues = msg.getResponseHeader().getHeaderValues(HTTP_HEADER_CSP);
        if (!cspHeaderValues.isEmpty()) {
            cspHeaderExists = true;
        }

        if (cspHeaderExists) {
            List<Notice> notices = new ArrayList<>();
            Origin origin = URI.parse(msg.getRequestHeader().getURI().toString());
            String policyText = cspHeaderValues.toString().replaceAll("[\\[\\]]","" );
            Policy policy = ParserWithLocation.parse(policyText, origin, notices);

            if (!notices.isEmpty()) {
                String cspNoticesString = gerCspNoticesString(notices);
                if (cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.errors"))
                        || cspNoticesString.contains(
                        Constant.messages.getString(MESSAGE_PREFIX + "notices.warnings"))) {
                    noticesRisk = Alert.RISK_LOW;
                } else {
                    noticesRisk = Alert.RISK_INFO;
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
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "wildcard.name"),
                        id,
                        wildcardSrcDesc,
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspHeaderValues.get(0));
            }

            if (policy.allowsUnsafeInlineScript()) {
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.name"),
                        id,
                        Constant.messages.getString(MESSAGE_PREFIX + "scriptsrc.unsafe.desc"),
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspHeaderValues.get(0));
            }

            if (policy.allowsUnsafeInlineStyle()) {
                raiseAlert(
                        msg,
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.name"),
                        id,
                        Constant.messages.getString(MESSAGE_PREFIX + "stylesrc.unsafe.desc"),
                        getHeaderField(msg, HTTP_HEADER_CSP).get(0),
                        Alert.RISK_MEDIUM,
                        cspHeaderValues.get(0));
            }

        } else {
            LOG.debug("CSP do not find!!!");
        }

        LOG.debug("\tScan of record "
                + id
                + " took "
                + (LocalDateTime.now().getSecond() - startTime)
                + " seconds");

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
            stringBuilder.append(Constant.messages.getString(MESSAGE_PREFIX, "notice.warnings"))
                    .append(NEWLINE);
            warnList
                    .forEach(notice -> stringBuilder.append(notice.show()).append(NEWLINE));
        }

        List<Notice> infoList = Notice.getAllInfos((ArrayList<Notice>) notices);
        if (!infoList.isEmpty()) {
            stringBuilder.append(Constant.messages.getString(MESSAGE_PREFIX, "notice.infoItems"))
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
    }

    private List<String> getAllowedWildcardSources(String policyText, Origin origin) {

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
}
