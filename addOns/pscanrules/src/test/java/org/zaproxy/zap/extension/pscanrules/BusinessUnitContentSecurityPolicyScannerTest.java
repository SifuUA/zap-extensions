package org.zaproxy.zap.extension.pscanrules;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.junit.Assert.assertEquals;

public class BusinessUnitContentSecurityPolicyScannerTest extends PassiveScannerTest<BusinessUnitContentSecurityPolicyScanner> {

    @Override
    protected BusinessUnitContentSecurityPolicyScanner createScanner() {
        return new BusinessUnitContentSecurityPolicyScanner();
    }

    @Test
    public void cspExample() throws HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage();
        message.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        message.setResponseBody("<html></html>");
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src: 'none'; report_uri /__cspreport__\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + message.getResponseBody().length()
                        + "\r\n");

        // When
        rule.scanHttpResponseReceive(message, -1, this.createSource(message));
        // Then
        assertEquals(alertsRaised.size(), 2);

    }

    @Test
    public void watsonsCSP() throws HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage();
        message.setRequestHeader("GET https://www.kruidvat.nl/ HTTP/1.1");

        message.setResponseBody("<html></html>");
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "x-frame-options: SAMEORIGIN\r\n"
                        + "strict-transport-security: max-age=31536000;includeSubDomains\r\n"
                        + "content-security-policy: default-src 'self'; frame-src 'self' https://service.kruidvat.nl https://campaign.kruidvat.be https://*.google.com https://player.vimeo.com https://*.hotjar.com https://*.trustarc.com https://stagconnect.acehubpaymentservices.com https://www.youtube.com https://nummerbehoud.portingxs.nl https://dot.vu https://*.bazaarvoice.com/; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.kruidvat.nl https://*.google.com https://*.googleapis.com https://www.gstatic.com https://*.googletagmanager.com https://*.google-analytics.com https://*.peerius.episerver.net https://*.peerius.com https://*.hotjar.com https://*.trustarc.com https://unless.com https://*.bazaarvoice.com https://*.vimeo.com https://vimeo.com https://secure.adnxs.com https://*.youtube.com https://s.ytimg.com https://s.go-mpulse.net https://mpsnare.iesnare.com; connect-src 'self' https://*.kruidvat.nl https://*.hotjar.com https://*.hotjar.io https://*.google-analytics.com https://*.peerius.com https://unless.com https://c.go-mpulse.net https://*.akstat.io; style-src 'self' 'unsafe-inline' https://*.googleapis.com https://*.google.com https://*.fontawesome.com https://*.bazaarvoice.com; font-src 'self' data: https://*.google.com https://*.gstatic.com https://*.hotjar.com https://*.fontawesome.com; img-src 'self' https: data: blob:\r\n"
                        + "x-frame-options: SAMEORIGIN\r\n"
                        + "x-content-type-options: nosniff\r\n"
                        + "x-xss-protection: 1; mode=block\r\n"
                        + "content-language: uk\r\n"
                        + "content-type: text/html;charset=UTF-8\r\n"
        );

        // When
        rule.scanHttpResponseReceive(message, -1, this.createSource(message));
        // Then
        assertEquals(alertsRaised.size(), 4);

    }
}