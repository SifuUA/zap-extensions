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
}