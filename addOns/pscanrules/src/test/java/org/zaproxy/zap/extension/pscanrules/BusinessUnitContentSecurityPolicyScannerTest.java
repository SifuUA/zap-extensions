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

    @Test(expected = NullPointerException.class)
    public void shouldThrowExceptionWhileComparingWithNotDefinedSite() throws HttpMalformedHeaderException {
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
    }

    @Test
    public void shouldRaiseTwoAlerts() throws HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage();
        message.setRequestHeader("GET https://www-pre-watsons-ua.uk.aswatson.net/ HTTP/1.1");

        message.setResponseBody("<html></html>");
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "x-frame-options: SAMEORIGIN\r\n"
                        + "strict-transport-security: max-age=31536000;includeSubDomains\r\n"
                        + "content-security-policy: default-src 'self' https://cdna.livechatinc.com https://*.doubleclick.net; frame-src 'self' https://platform.twitter.com https://*.google.com https://*.doubleclick.net https://*.livechatinc.com https://*.hotjar.com https://*.facebook.com https://*.liqpay.ua https://*.youtube.com https://dot.vu; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://livechat.chat24.io https://*.rackcdn.com https://x01.aidata.io https://platform.twitter.com https://*.google.com https://*.aswatson.net https://*.googleapis.com https://*.googletagmanager.com https://*.google-analytics.com https://*.googleadservices.com https://*.feefo.com https://*.doubleclick.net https://*.artfut.com https://pafutos.com https://lenkmio.com https://*.admitad.com https://*.asbmit.com https://*.facebook.net https://*.gstatic.com https://*.gravitec.net https://*.hotjar.com https://*.livechatinc.com https://*.liqpay.ua https://*.peerius.com https://*.episerver.net https://*.telemayak.net https://*.newrelic.com https://*.nr-data.net https://*.ag0oir9f.de https://*.go-mpulse.net https://granit.uislab.com https://inv-dmp.admixer.net; connect-src 'self' https://*.aswatson.net https://*.google-analytics.com https://livechat.chat24.io wss://livechat.chat24.io https://*.feefo.com https://*.episerver.net https://*.peerius.com https://*.29apfjmg2.de https://*.hotjar.com https://*.hotjar.io https://*.facebook.com https://*.telemayak.net https://*.gravitec.net https://ag0oir9f.de https://*.go-mpulse.net https://*.akstat.io https://*.akamaihd.net wss://*.hotjar.com https://granit.uislab.com https://bam.nr-data.net; style-src 'self' 'unsafe-inline' https://livechat.chat24.io https://maxcdn.bootstrapcdn.com https://use.fontawesome.com https://*.aswatson.net https://*.google.com https://*.googleapis.com; font-src 'self' data: https://livechat.chat24.io https://use.fontawesome.com https://maxcdn.bootstrapcdn.com https://*.googleapis.com https://*.gstatic.com; img-src 'self' data: https://livechat.chat24.io https://x01.aidata.io https://gen.sendtric.com https://*.aswatson.net https://artfut.com https://pafutos.com https://*.asbmit.com https://*.admitad.com https://lenkmio.com https://ag0oir9f.de https://*.google.ru https://*.gstatic.com https://*.googleapis.com https://*.google.com https://*.google.com.ua https://*.google-analytics.com https://*.googletagmanager.com  https://granit.uislab.com https://*.watsons.ua https://*.doubleclick.net https://*.facebook.com https://*.livechatinc.com https://*.amazonaws.com https://x01.aidata.io https://sync.1dmp.io https://px.adhigh.net https://counter.yadro.ru https://sync.crwdcntrl.net https://sync.upravel.com https://ad.mail.ru https://cm.p.altergeo.ru https://an.yandex.ru https://ps.eyeota.net https://cdn.gravitec.net;\r\n"
                        + "x-content-type-options: nosniff\r\n"
                        + "x-xss-protection: 1; mode=block\r\n"
                        + "content-language: uk\r\n"
                        + "content-type: text/html;charset=UTF-8\r\n"
        );

        rule.scanHttpResponseReceive(message, -1, this.createSource(message));
        assertEquals(alertsRaised.size(), 2);
    }

    @Test
    public void shouldNotRaiseAnyAlerts() throws HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage();
        message.setRequestHeader("GET https://www-pre-watsons-ua.uk.aswatson.net/ HTTP/1.1");

        message.setResponseBody("<html></html>");
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "x-frame-options: SAMEORIGIN\r\n"
                        + "strict-transport-security: max-age=31536000;includeSubDomains\r\n"
                        + "content-security-policy: default-src 'self' https://*.livechatinc.com https://*.doubleclick.net https://*.mysite.net; frame-src 'self' https://platforam.twitter.com https://*.google.com https://*.doubleclick.net https://*.livechatinc.com https://*.hotjar.com https://*.facebook.com https://*.liqpay.ua https://*.youtube.com https://dot.vu; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://livechat.chat24.io https://*.rackcdn.com https://x01.aidata.io https://platform.twitter.com https://*.google.com https://*.aswatson.net https://*.googleapis.com https://*.googletagmanager.com https://*.google-analytics.com https://*.googleadservices.com https://*.feefo.com https://*.doubleclick.net https://*.artfut.com https://pafutos.com https://lenkmio.com https://*.admitad.com https://*.asbmit.com https://*.facebook.net https://*.gstatic.com https://*.gravitec.net https://*.hotjar.com https://*.livechatinc.com https://*.liqpay.ua https://*.peerius.com https://*.episerver.net https://*.telemayak.net https://*.newrelic.com https://*.nr-data.net https://*.ag0oir9f.de https://*.go-mpulse.net https://granit.uislab.com https://inv-dmp.admixer.net; connect-src 'self' https://*.aswatson.net https://*.google-analytics.com https://livechat.chat24.io wss://livechat.chat24.io https://*.feefo.com https://*.episerver.net https://*.peerius.com https://*.29apfjmg2.de https://*.hotjar.com https://*.hotjar.io https://*.facebook.com https://*.telemayak.net https://*.gravitec.net https://ag0oir9f.de https://*.go-mpulse.net https://*.akstat.io https://*.akamaihd.net wss://*.hotjar.com https://granit.uislab.com https://bam.nr-data.net; style-src 'self' 'unsafe-inline' https://livechat.chat24.io https://maxcdn.bootstrapcdn.com https://use.fontawesome.com https://*.aswatson.net https://*.google.com https://*.googleapis.com; font-src 'self' data: https://livechat.chat24.io https://use.fontawesome.com https://maxcdn.bootstrapcdn.com https://*.googleapis.com https://*.gstatic.com; img-src 'self' data: https://livechat.chat24.io https://x01.aidata.io https://gen.sendtric.com https://*.aswatson.net https://artfut.com https://pafutos.com https://*.asbmit.com https://*.admitad.com https://lenkmio.com https://ag0oir9f.de https://*.google.ru https://*.gstatic.com https://*.googleapis.com https://*.google.com https://*.google.com.ua https://*.google-analytics.com https://*.googletagmanager.com  https://granit.uislab.com https://*.watsons.ua https://*.doubleclick.net https://*.facebook.com https://*.livechatinc.com https://*.amazonaws.com https://x01.aidata.io https://sync.1dmp.io https://px.adhigh.net https://counter.yadro.ru https://sync.crwdcntrl.net https://sync.upravel.com https://ad.mail.ru https://cm.p.altergeo.ru https://an.yandex.ru https://ps.eyeota.net https://cdn.gravitec.net;\r\n"
                        + "x-content-type-options: nosniff\r\n"
                        + "x-xss-protection: 1; mode=block\r\n"
                        + "content-language: uk\r\n"
                        + "content-type: text/html;charset=UTF-8\r\n"
        );

        rule.scanHttpResponseReceive(message, -1, this.createSource(message));
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldRaiseAlerts() throws HttpMalformedHeaderException {
        HttpMessage message = new HttpMessage();
        message.setRequestHeader("GET https://www.theperfumeshop.com// HTTP/1.1");

        message.setResponseBody("<html></html>");
        message.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "x-frame-options: SAMEORIGIN\r\n"
                        + "strict-transport-security: max-age=31536000;includeSubDomains\r\n"
                        + "content-security-policy:  default-src 'self' https://*.uk.aswatson.net; object-src 'self' blob: https://*.doubleclick.net https://*.hotjar.com https://*.bazaarvoice.com https://*.worldpay.com https://*.co-buying.com; frame-src 'self' blob: https://*.doubleclick.net https://*.hotjar.com https://*.bazaarvoice.com https://*.worldpay.com https://*.trustarc.com https://*.facebook.com https://*.devatics.io https://*.addthis.com https://*.google.com https://*.youtube.com https://fragrance-finder.mesh.mx https://*.tradedoubler.com https://*.studentbeans.com https://*.co-buying.com https://*.rackcdn.com https://*.youtube.com https://dot.vu https://isitetv.com https://*.facebook.net https://*.eventbrite.co.uk https://*.adform.net https://lightwidget.com https://*.twitter.com https://*.constant.co https://*.gnatta.com https://*.official-coupons.com https://theperfumeshop.api.useinsider.com https://d3jdlwnuo8nsnr.cloudfront.net https://*.youthdiscount.com https://fragrancediagnostic.one.dior.com https://uk.parfumado.com https://*.parfumado.com https://parfumado.com https://*.klarna.com https://*.spotify.com https://crosswordlabs.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: https://*.googleapis.com https://*.feefo.com https://*.doubleclick.net https://*.googletagmanager.com https://*.googleadservices.com https://*.peerius.com https://*.hotjar.com https://*.google-analytics.com https://*.truste.com https://*.trustarc.com https://*.facebook.net https://*.facebook.com https://*.bazaarvoice.com https://*.worldpay.com https://*.google.com https://*.devatics.io https://*.devatics.com https://*.cloudflare.com https://*.addthis.com https://*.addthisedge.com https://*.zendesk.com https://*.zdassets.com https://*.gstatic.com https://*.zopim.com https://*.aswatson.net https://*.serving-sys.com https://*.adform.net https://*.ads-twitter.com https://*.newrelic.com https://*.bing.com https://*.ascend.ai https://cdn.optimizely.com https://*.nr-data.net https://*.twitter.com https://*.co-buying.com https://*.studentbeans.com https://*.episerver.net https://*.rackcdn.com https://*.isitetv.com https://*.youtube.com https://*.ytimg.com https://*.eventbrite.co.uk https://*.goinstore.com https://*.opentok.com https://*.zencdn.net https://*.jsdelivr.net https://*.onestock-retail.io https://*.lightwidget.com https://lightwidget.com https://*.syndication.twimg.com https://*.constant.co https://*.revlifter.io https://*.official-coupons.com https://*.official-deals.co.uk https://*.gnatta.com https://*.useinsider.com https://*.contentsquare.net https://*.cloudfront.net https://s.go-mpulse.net https://*.klarnacdn.net; connect-src 'self' https://bam.nr-data.net https://*.googleapis.com https://*.google-analytics.com https://*.facebook.com https://*.feefo.com https://*.hotjar.com https://*.hotjar.io wss://*.hotjar.com https://*.bazaarvoice.com https://*.worldpay.com https://*.justshoutgfs.com https://*.addthis.com https://*.fragrancesoftheworld.com https://*.ovolab.com https://*.zdassets.com https://*.zendesk.com https://*.zopim.com wss://*.zopim.com https://*.serving-sys.com https://*.facebook.com https://*.twitter.com https://*.co-buying.com https://*.goinstore.com https://*.loggly.com https://*.tokbox.com https://*.opentok.com wss://*.tokbox.com https://*.episerver.net https://*.peerius.com https://*.constant.co https://*.gnatta.com https://*.revlifter.io https://*.contentsquare.net https://c.go-mpulse.net https://*.akstat.io https://*.akamaihd.net https://*.klarna.com; style-src 'self' 'unsafe-inline' https://*.googleapis.com https://*.google.com https://*.bazaarvoice.com https://*.worldpay.com https://*.revieve.com https://*.fontawesome.com https://*.hotjar.com https://*.devatics.io https://*.devatics.com https://*.goinstore.com https://*.zencdn.net https://*.uk.aswatson.net https://*.twitter.com; font-src 'self' data: https://*.google.com https://*.googleapis.com https://*.gstatic.com https://*.hotjar.com https://*.theperfumeshop.com https://*.zopim.com https://*.fontawesome.com https://*.uk.aswatson.net https://*.tradedoubler.com https://*.devatics.io https://cdnjs.cloudflare.com; img-src 'self' https: data: blob: https://*.theperfumeshop.com https://*.hotjar.com; media-src 'self' blob: https://*.goinstore.com https://*.theperfumeshop.com https://*.fbcdn.net; worker-src 'self' blob: https://*.theperfumeshop.com; prefetch-src 'self' 'unsafe-inline' 'unsafe-eval' data: https://*.klarnacdn.net;\r\n"
                        + "x-content-type-options: nosniff\r\n"
                        + "x-xss-protection: 1; mode=block\r\n"
                        + "content-language: uk\r\n"
                        + "content-type: text/html;charset=UTF-8\r\n"
        );

        rule.scanHttpResponseReceive(message, -1, this.createSource(message));
        assertEquals(alertsRaised.size(), 2);
    }
}
