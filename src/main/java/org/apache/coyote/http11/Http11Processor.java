//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.apache.coyote.http11;

import org.apache.coyote.*;
import org.apache.coyote.http11.filters.*;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.ContextBind;
import org.apache.tomcat.InstanceManager;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.FastHttpDateFormat;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.http.parser.TokenList;
import org.apache.tomcat.util.log.UserDataHelper.Mode;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.SendfileDataBase;
import org.apache.tomcat.util.net.SendfileKeepAliveState;
import org.apache.tomcat.util.net.SendfileState;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.res.StringManager;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.regex.Pattern;

public class Http11Processor extends AbstractProcessor {
    private static final Log log = LogFactory.getLog(Http11Processor.class);
    private static final StringManager sm = StringManager.getManager(Http11Processor.class);
    private final AbstractHttp11Protocol<?> protocol;
    private final Http11InputBuffer inputBuffer;
    private final Http11OutputBuffer outputBuffer;
    private final HttpParser httpParser;
    private int pluggableFilterIndex = 2147483647;
    private volatile boolean keepAlive = true;
    private boolean openSocket = false;
    private boolean readComplete = true;
    private boolean http11 = true;
    private boolean http09 = false;
    private boolean contentDelimitation = true;
    private UpgradeToken upgradeToken = null;
    private SendfileDataBase sendfileData = null;

    public Http11Processor(AbstractHttp11Protocol<?> protocol, Adapter adapter) {
        super(adapter);
        this.protocol = protocol;
        this.httpParser = new HttpParser(protocol.getRelaxedPathChars(), protocol.getRelaxedQueryChars());
        this.inputBuffer = new Http11InputBuffer(this.request, protocol.getMaxHttpHeaderSize(), protocol.getRejectIllegalHeader(), this.httpParser);
        this.request.setInputBuffer(this.inputBuffer);
        this.outputBuffer = new Http11OutputBuffer(this.response, protocol.getMaxHttpHeaderSize());
        this.response.setOutputBuffer(this.outputBuffer);
        this.inputBuffer.addFilter(new IdentityInputFilter(protocol.getMaxSwallowSize()));
        this.outputBuffer.addFilter(new IdentityOutputFilter());
        this.inputBuffer.addFilter(new ChunkedInputFilter(protocol.getMaxTrailerSize(), protocol.getAllowedTrailerHeadersInternal(), protocol.getMaxExtensionSize(), protocol.getMaxSwallowSize()));
        this.outputBuffer.addFilter(new ChunkedOutputFilter());
        this.inputBuffer.addFilter(new VoidInputFilter());
        this.outputBuffer.addFilter(new VoidOutputFilter());
        this.inputBuffer.addFilter(new BufferedInputFilter());
        this.outputBuffer.addFilter(new GzipOutputFilter());
        this.pluggableFilterIndex = this.inputBuffer.getFilters().length;
    }

    private static boolean statusDropsConnection(int status) {
        return status == 400 || status == 408 || status == 411 || status == 413 || status == 414 || status == 500 || status == 503 || status == 501;
    }

    private void addInputFilter(InputFilter[] inputFilters, String encodingName) {
        if (!encodingName.equals("identity")) {
            if (encodingName.equals("chunked")) {
                this.inputBuffer.addActiveFilter(inputFilters[1]);
                this.contentDelimitation = true;
            } else {
                for(int i = this.pluggableFilterIndex; i < inputFilters.length; ++i) {
                    if (inputFilters[i].getEncodingName().toString().equals(encodingName)) {
                        this.inputBuffer.addActiveFilter(inputFilters[i]);
                        return;
                    }
                }

                this.response.setStatus(501);
                this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http11processor.request.prepare") + " Unsupported transfer encoding [" + encodingName + "]");
                }
            }
        }

    }

    public SocketState service(SocketWrapperBase<?> socketWrapper) throws IOException {
        RequestInfo rp = this.request.getRequestProcessor();
        rp.setStage(1);
        this.setSocketWrapper(socketWrapper);
        this.keepAlive = true;
        this.openSocket = false;
        this.readComplete = true;
        boolean keptAlive = false;

        SendfileState sendfileState;
        for(sendfileState = SendfileState.DONE; !this.getErrorState().isError() && this.keepAlive && !this.isAsync() && this.upgradeToken == null && sendfileState == SendfileState.DONE && !this.protocol.isPaused(); sendfileState = this.processSendfile(socketWrapper)) {
            try {
                if (!this.inputBuffer.parseRequestLine(keptAlive, this.protocol.getConnectionTimeout(), this.protocol.getKeepAliveTimeout())) {
                    if (this.inputBuffer.getParsingRequestLinePhase() == -1) {
                        return SocketState.UPGRADING;
                    }

                    if (this.handleIncompleteRequestLineRead()) {
                        break;
                    }
                }

                this.prepareRequestProtocol();
                if (this.protocol.isPaused()) {
                    this.response.setStatus(503);
                    this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
                } else {
                    keptAlive = true;
                    this.request.getMimeHeaders().setLimit(this.protocol.getMaxHeaderCount());
                    if (!this.http09 && !this.inputBuffer.parseHeaders()) {
                        this.openSocket = true;
                        this.readComplete = false;
                        break;
                    }

                    if (!this.protocol.getDisableUploadTimeout()) {
                        socketWrapper.setReadTimeout((long)this.protocol.getConnectionUploadTimeout());
                    }
                }
            } catch (IOException var13) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http11processor.header.parse"), var13);
                }

                this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, var13);
                break;
            } catch (Throwable var14) {
                ExceptionUtils.handleThrowable(var14);
                Mode logMode = this.userDataHelper.getNextMode();
                if (logMode != null) {
                    String message = sm.getString("http11processor.header.parse");
                    switch(logMode) {
                        case INFO_THEN_DEBUG:
                            message = message + sm.getString("http11processor.fallToDebug");
                        case INFO:
                            log.info(message, var14);
                            break;
                        case DEBUG:
                            log.debug(message, var14);
                    }
                }

                this.response.setStatus(400);
                this.setErrorState(ErrorState.CLOSE_CLEAN, var14);
            }

            if (isConnectionToken(this.request.getMimeHeaders(), "upgrade")) {
                String requestedProtocol = this.request.getHeader("Upgrade");
                UpgradeProtocol upgradeProtocol = this.protocol.getUpgradeProtocol(requestedProtocol);
                if (upgradeProtocol != null && upgradeProtocol.accept(this.request)) {
                    this.response.setStatus(101);
                    this.response.setHeader("Connection", "Upgrade");
                    this.response.setHeader("Upgrade", requestedProtocol);
                    this.action(ActionCode.CLOSE, (Object)null);
                    this.getAdapter().log(this.request, this.response, 0L);
                    InternalHttpUpgradeHandler upgradeHandler = upgradeProtocol.getInternalUpgradeHandler(socketWrapper, this.getAdapter(), this.cloneRequest(this.request));
                    UpgradeToken upgradeToken = new UpgradeToken(upgradeHandler, (ContextBind)null, (InstanceManager)null, requestedProtocol);
                    this.action(ActionCode.UPGRADE, upgradeToken);
                    return SocketState.UPGRADING;
                }
            }

            if (this.getErrorState().isIoAllowed()) {
                rp.setStage(2);

                try {
                    this.prepareRequest();
                } catch (Throwable var12) {
                    ExceptionUtils.handleThrowable(var12);
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("http11processor.request.prepare"), var12);
                    }

                    this.response.setStatus(500);
                    this.setErrorState(ErrorState.CLOSE_CLEAN, var12);
                }
            }

            /****************  tomcat.query.char.convert   ***********************/
            String serverName = request.serverName().toString();
            String queryUri = request.requestURI().toString();
            String queryStr = request.queryString().toString();

            String configString = System.getProperty("tomcat.query.char.convert","*,*,{}[]|,utf-8;");
            List<String> configs = Arrays.asList(configString.split(";"));
            for (String config:configs){
                String[] ss = config.split(",");
                String host = ss[0];
                String uri = ss[1];
                String chars = ss[2];
                String enc = ss[3];
                if ( ("*".equals(host) || serverName.contains(host)) && ( "*".equals(uri) || queryUri.contains(uri) )){

                    if (chars != null && chars.length() > 0 && queryStr != null) {
                        for (String s : chars.split("")) {
                            queryStr = queryStr.replace(s, URLEncoder.encode(s, enc));
                        }
                        request.queryString().setString(queryStr);
                    }

                    break;
                }
            }

            int maxKeepAliveRequests = this.protocol.getMaxKeepAliveRequests();
            if (maxKeepAliveRequests == 1) {
                this.keepAlive = false;
            } else if (maxKeepAliveRequests > 0 && socketWrapper.decrementKeepAlive() <= 0) {
                this.keepAlive = false;
            }

            if (this.getErrorState().isIoAllowed()) {
                try {
                    rp.setStage(3);
                    this.getAdapter().service(this.request, this.response);
                    if (this.keepAlive && !this.getErrorState().isError() && !this.isAsync() && statusDropsConnection(this.response.getStatus())) {
                        this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
                    }
                } catch (InterruptedIOException var9) {
                    this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, var9);
                } catch (HeadersTooLargeException var10) {
                    log.error(sm.getString("http11processor.request.process"), var10);
                    if (this.response.isCommitted()) {
                        this.setErrorState(ErrorState.CLOSE_NOW, var10);
                    } else {
                        this.response.reset();
                        this.response.setStatus(500);
                        this.setErrorState(ErrorState.CLOSE_CLEAN, var10);
                        this.response.setHeader("Connection", "close");
                    }
                } catch (Throwable var11) {
                    ExceptionUtils.handleThrowable(var11);
                    log.error(sm.getString("http11processor.request.process"), var11);
                    this.response.setStatus(500);
                    this.setErrorState(ErrorState.CLOSE_CLEAN, var11);
                    this.getAdapter().log(this.request, this.response, 0L);
                }
            }

            rp.setStage(4);
            if (!this.isAsync()) {
                this.endRequest();
            }

            rp.setStage(5);
            if (this.getErrorState().isError()) {
                this.response.setStatus(500);
            }

            if (!this.isAsync() || this.getErrorState().isError()) {
                this.request.updateCounters();
                if (this.getErrorState().isIoAllowed()) {
                    this.inputBuffer.nextRequest();
                    this.outputBuffer.nextRequest();
                }
            }

            if (!this.protocol.getDisableUploadTimeout()) {
                int connectionTimeout = this.protocol.getConnectionTimeout();
                if (connectionTimeout > 0) {
                    socketWrapper.setReadTimeout((long)connectionTimeout);
                } else {
                    socketWrapper.setReadTimeout(0L);
                }
            }

            rp.setStage(6);
        }

        rp.setStage(7);
        if (this.getErrorState().isError() || this.protocol.isPaused() && !this.isAsync()) {
            return SocketState.CLOSED;
        } else if (this.isAsync()) {
            return SocketState.LONG;
        } else if (this.isUpgrade()) {
            return SocketState.UPGRADING;
        } else if (sendfileState == SendfileState.PENDING) {
            return SocketState.SENDFILE;
        } else if (this.openSocket) {
            return this.readComplete ? SocketState.OPEN : SocketState.LONG;
        } else {
            return SocketState.CLOSED;
        }
    }

    protected final void setSocketWrapper(SocketWrapperBase<?> socketWrapper) {
        super.setSocketWrapper(socketWrapper);
        this.inputBuffer.init(socketWrapper);
        this.outputBuffer.init(socketWrapper);
    }

    private Request cloneRequest(Request source) throws IOException {
        Request dest = new Request();
        dest.decodedURI().duplicate(source.decodedURI());
        dest.method().duplicate(source.method());
        dest.getMimeHeaders().duplicate(source.getMimeHeaders());
        dest.requestURI().duplicate(source.requestURI());
        dest.queryString().duplicate(source.queryString());
        return dest;
    }

    private boolean handleIncompleteRequestLineRead() {
        this.openSocket = true;
        if (this.inputBuffer.getParsingRequestLinePhase() > 1) {
            if (this.protocol.isPaused()) {
                this.response.setStatus(503);
                this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
                return false;
            }

            this.readComplete = false;
        }

        return true;
    }

    private void checkExpectationAndResponseStatus() {
        if (this.request.hasExpectation() && !this.isRequestBodyFullyRead() && (this.response.getStatus() < 200 || this.response.getStatus() > 299)) {
            this.inputBuffer.setSwallowInput(false);
            this.keepAlive = false;
        }

    }

    private void checkMaxSwallowSize() {
        long contentLength = -1L;

        try {
            contentLength = this.request.getContentLengthLong();
        } catch (Exception var4) {
        }

        if (contentLength > 0L && this.protocol.getMaxSwallowSize() > -1 && contentLength - this.request.getBytesRead() > (long)this.protocol.getMaxSwallowSize()) {
            this.keepAlive = false;
        }

    }

    private void prepareRequestProtocol() {
        MessageBytes protocolMB = this.request.protocol();
        if (protocolMB.equals("HTTP/1.1")) {
            this.http09 = false;
            this.http11 = true;
            protocolMB.setString("HTTP/1.1");
        } else if (protocolMB.equals("HTTP/1.0")) {
            this.http09 = false;
            this.http11 = false;
            this.keepAlive = false;
            protocolMB.setString("HTTP/1.0");
        } else if (protocolMB.equals("")) {
            this.http09 = true;
            this.http11 = false;
            this.keepAlive = false;
        } else {
            this.http09 = false;
            this.http11 = false;
            this.response.setStatus(505);
            this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http11processor.request.prepare") + " Unsupported HTTP version \"" + protocolMB + "\"");
            }
        }

    }

    private void prepareRequest() throws IOException {
        this.contentDelimitation = false;
        if (this.protocol.isSSLEnabled()) {
            this.request.scheme().setString("https");
        }

        MimeHeaders headers = this.request.getMimeHeaders();
        MessageBytes connectionValueMB = headers.getValue("Connection");
        if (connectionValueMB != null && !connectionValueMB.isNull()) {
            Set<String> tokens = new HashSet();
            TokenList.parseTokenList(headers.values("Connection"), tokens);
            if (tokens.contains("close")) {
                this.keepAlive = false;
            } else if (tokens.contains("keep-alive")) {
                this.keepAlive = true;
            }
        }

        if (this.http11) {
            MessageBytes expectMB = headers.getValue("expect");
            if (expectMB != null && !expectMB.isNull()) {
                if (expectMB.toString().trim().equalsIgnoreCase("100-continue")) {
                    this.inputBuffer.setSwallowInput(false);
                    this.request.setExpectation(true);
                } else {
                    this.response.setStatus(417);
                    this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
                }
            }
        }

        Pattern restrictedUserAgents = this.protocol.getRestrictedUserAgentsPattern();
        MessageBytes hostValueMB;
        if (restrictedUserAgents != null && (this.http11 || this.keepAlive)) {
            hostValueMB = headers.getValue("user-agent");
            if (hostValueMB != null && !hostValueMB.isNull()) {
                String userAgentValue = hostValueMB.toString();
                if (restrictedUserAgents.matcher(userAgentValue).matches()) {
                    this.http11 = false;
                    this.keepAlive = false;
                }
            }
        }

        hostValueMB = null;

        try {
            hostValueMB = headers.getUniqueValue("host");
        } catch (IllegalArgumentException var15) {
            this.badRequest("http11processor.request.multipleHosts");
        }

        if (this.http11 && hostValueMB == null) {
            this.badRequest("http11processor.request.noHostHeader");
        }

        ByteChunk uriBC = this.request.requestURI().getByteChunk();
        byte[] uriB = uriBC.getBytes();
        int pos;
        if (uriBC.startsWithIgnoreCase("http", 0)) {
            pos = 4;
            if (uriBC.startsWithIgnoreCase("s", pos)) {
                ++pos;
            }

            if (uriBC.startsWith("://", pos)) {
                pos += 3;
                int uriBCStart = uriBC.getStart();
                int slashPos = uriBC.indexOf('/', pos);
                int atPos = uriBC.indexOf('@', pos);
                if (slashPos > -1 && atPos > slashPos) {
                    atPos = -1;
                }

                if (slashPos == -1) {
                    slashPos = uriBC.getLength();
                    this.request.requestURI().setBytes(uriB, uriBCStart + 6, 1);
                } else {
                    this.request.requestURI().setBytes(uriB, uriBCStart + slashPos, uriBC.getLength() - slashPos);
                }

                if (atPos != -1) {
                    while(pos < atPos) {
                        byte c = uriB[uriBCStart + pos];
                        if (!HttpParser.isUserInfo(c)) {
                            this.badRequest("http11processor.request.invalidUserInfo");
                            break;
                        }

                        ++pos;
                    }

                    pos = atPos + 1;
                }

                if (this.http11) {
                    if (hostValueMB != null && !hostValueMB.getByteChunk().equals(uriB, uriBCStart + pos, slashPos - pos)) {
                        if (this.protocol.getAllowHostHeaderMismatch()) {
                            hostValueMB = headers.setValue("host");
                            hostValueMB.setBytes(uriB, uriBCStart + pos, slashPos - pos);
                        } else {
                            this.badRequest("http11processor.request.inconsistentHosts");
                        }
                    }
                } else {
                    try {
                        hostValueMB = headers.setValue("host");
                        hostValueMB.setBytes(uriB, uriBCStart + pos, slashPos - pos);
                    } catch (IllegalStateException var14) {
                    }
                }
            } else {
                this.badRequest("http11processor.request.invalidScheme");
            }
        }

        for(pos = uriBC.getStart(); pos < uriBC.getEnd(); ++pos) {
            if (!this.httpParser.isAbsolutePathRelaxed(uriB[pos])) {
                this.badRequest("http11processor.request.invalidUri");
                break;
            }
        }

        InputFilter[] inputFilters = this.inputBuffer.getFilters();
        if (this.http11) {
            MessageBytes transferEncodingValueMB = headers.getValue("transfer-encoding");
            if (transferEncodingValueMB != null) {
                List<String> encodingNames = new ArrayList();
                if (TokenList.parseTokenList(headers.values("transfer-encoding"), encodingNames)) {
                    Iterator var23 = encodingNames.iterator();

                    while(var23.hasNext()) {
                        String encodingName = (String)var23.next();
                        this.addInputFilter(inputFilters, encodingName);
                    }
                } else {
                    this.badRequest("http11processor.request.invalidTransferEncoding");
                }
            }
        }

        long contentLength = -1L;

        try {
            contentLength = this.request.getContentLengthLong();
        } catch (NumberFormatException var12) {
            this.badRequest("http11processor.request.nonNumericContentLength");
        } catch (IllegalArgumentException var13) {
            this.badRequest("http11processor.request.multipleContentLength");
        }

        if (contentLength >= 0L) {
            if (this.contentDelimitation) {
                headers.removeHeader("content-length");
                this.request.setContentLength(-1L);
            } else {
                this.inputBuffer.addActiveFilter(inputFilters[0]);
                this.contentDelimitation = true;
            }
        }

        this.parseHost(hostValueMB);
        if (!this.contentDelimitation) {
            this.inputBuffer.addActiveFilter(inputFilters[2]);
            this.contentDelimitation = true;
        }

        if (!this.getErrorState().isIoAllowed()) {
            this.getAdapter().log(this.request, this.response, 0L);
        }

    }

    private void badRequest(String errorKey) {
        this.response.setStatus(400);
        this.setErrorState(ErrorState.CLOSE_CLEAN, (Throwable)null);
        if (log.isDebugEnabled()) {
            log.debug(sm.getString(errorKey));
        }

    }

    protected final void prepareResponse() throws IOException {
        boolean entityBody = true;
        this.contentDelimitation = false;
        OutputFilter[] outputFilters = this.outputBuffer.getFilters();
        if (this.http09) {
            this.outputBuffer.addActiveFilter(outputFilters[0]);
            this.outputBuffer.commit();
        } else {
            int statusCode = this.response.getStatus();
            if (statusCode < 200 || statusCode == 204 || statusCode == 205 || statusCode == 304) {
                this.outputBuffer.addActiveFilter(outputFilters[2]);
                entityBody = false;
                this.contentDelimitation = true;
                if (statusCode == 205) {
                    this.response.setContentLength(0L);
                } else {
                    this.response.setContentLength(-1L);
                }
            }

            MessageBytes methodMB = this.request.method();
            if (methodMB.equals("HEAD")) {
                this.outputBuffer.addActiveFilter(outputFilters[2]);
                this.contentDelimitation = true;
            }

            if (this.protocol.getUseSendfile()) {
                this.prepareSendfile(outputFilters);
            }

            boolean useCompression = false;
            if (entityBody && this.sendfileData == null) {
                useCompression = this.protocol.useCompression(this.request, this.response);
            }

            MimeHeaders headers = this.response.getMimeHeaders();
            if (entityBody || statusCode == 204) {
                String contentType = this.response.getContentType();
                if (contentType != null) {
                    headers.setValue("Content-Type").setString(contentType);
                }

                String contentLanguage = this.response.getContentLanguage();
                if (contentLanguage != null) {
                    headers.setValue("Content-Language").setString(contentLanguage);
                }
            }

            long contentLength = this.response.getContentLengthLong();
            boolean connectionClosePresent = isConnectionToken(headers, "close");
            if (this.http11 && this.response.getTrailerFields() != null) {
                this.outputBuffer.addActiveFilter(outputFilters[1]);
                this.contentDelimitation = true;
                headers.addValue("Transfer-Encoding").setString("chunked");
            } else if (contentLength != -1L) {
                headers.setValue("Content-Length").setLong(contentLength);
                this.outputBuffer.addActiveFilter(outputFilters[0]);
                this.contentDelimitation = true;
            } else if (this.http11 && entityBody && !connectionClosePresent) {
                this.outputBuffer.addActiveFilter(outputFilters[1]);
                this.contentDelimitation = true;
                headers.addValue("Transfer-Encoding").setString("chunked");
            } else {
                this.outputBuffer.addActiveFilter(outputFilters[0]);
            }

            if (useCompression) {
                this.outputBuffer.addActiveFilter(outputFilters[3]);
            }

            if (headers.getValue("Date") == null) {
                headers.addValue("Date").setString(FastHttpDateFormat.getCurrentDate());
            }

            if (entityBody && !this.contentDelimitation || connectionClosePresent) {
                this.keepAlive = false;
            }

            this.checkExpectationAndResponseStatus();
            this.checkMaxSwallowSize();
            if (this.keepAlive && statusDropsConnection(statusCode)) {
                this.keepAlive = false;
            }

            int keepAliveTimeout;
            if (!this.keepAlive) {
                if (!connectionClosePresent) {
                    headers.addValue("Connection").setString("close");
                }
            } else if (!this.getErrorState().isError()) {
                if (!this.http11) {
                    headers.addValue("Connection").setString("keep-alive");
                }

                if (this.protocol.getUseKeepAliveResponseHeader()) {
                    boolean connectionKeepAlivePresent = isConnectionToken(this.request.getMimeHeaders(), "keep-alive");
                    if (connectionKeepAlivePresent) {
                        keepAliveTimeout = this.protocol.getKeepAliveTimeout();
                        if (keepAliveTimeout > 0) {
                            String value = "timeout=" + (long)keepAliveTimeout / 1000L;
                            headers.setValue("Keep-Alive").setString(value);
                            if (this.http11) {
                                MessageBytes connectionHeaderValue = headers.getValue("Connection");
                                if (connectionHeaderValue == null) {
                                    headers.addValue("Connection").setString("keep-alive");
                                } else {
                                    connectionHeaderValue.setString(connectionHeaderValue.getString() + ", " + "keep-alive");
                                }
                            }
                        }
                    }
                }
            }

            String server = this.protocol.getServer();
            if (server == null) {
                if (this.protocol.getServerRemoveAppProvidedValues()) {
                    headers.removeHeader("server");
                }
            } else {
                headers.setValue("Server").setString(server);
            }

            try {
                this.outputBuffer.sendStatus();
                keepAliveTimeout = headers.size();

                for(int i = 0; i < keepAliveTimeout; ++i) {
                    this.outputBuffer.sendHeader(headers.getName(i), headers.getValue(i));
                }

                this.outputBuffer.endHeaders();
            } catch (Throwable var14) {
                ExceptionUtils.handleThrowable(var14);
                this.outputBuffer.resetHeaderBuffer();
                throw var14;
            }

            this.outputBuffer.commit();
        }
    }

    private static boolean isConnectionToken(MimeHeaders headers, String token) throws IOException {
        MessageBytes connection = headers.getValue("Connection");
        if (connection == null) {
            return false;
        } else {
            Set<String> tokens = new HashSet();
            TokenList.parseTokenList(headers.values("Connection"), tokens);
            return tokens.contains(token);
        }
    }

    private void prepareSendfile(OutputFilter[] outputFilters) {
        String fileName = (String)this.request.getAttribute("org.apache.tomcat.sendfile.filename");
        if (fileName == null) {
            this.sendfileData = null;
        } else {
            this.outputBuffer.addActiveFilter(outputFilters[2]);
            this.contentDelimitation = true;
            long pos = (Long)this.request.getAttribute("org.apache.tomcat.sendfile.start");
            long end = (Long)this.request.getAttribute("org.apache.tomcat.sendfile.end");
            this.sendfileData = this.socketWrapper.createSendfileData(fileName, pos, end - pos);
        }

    }

    protected void populatePort() {
        this.request.action(ActionCode.REQ_LOCALPORT_ATTRIBUTE, this.request);
        this.request.setServerPort(this.request.getLocalPort());
    }

    protected boolean flushBufferedWrite() throws IOException {
        if (this.outputBuffer.hasDataToWrite() && this.outputBuffer.flushBuffer(false)) {
            this.outputBuffer.registerWriteInterest();
            return true;
        } else {
            return false;
        }
    }

    protected SocketState dispatchEndRequest() {
        if (this.keepAlive && !this.protocol.isPaused()) {
            this.endRequest();
            this.inputBuffer.nextRequest();
            this.outputBuffer.nextRequest();
            return this.socketWrapper.isReadPending() ? SocketState.LONG : SocketState.OPEN;
        } else {
            return SocketState.CLOSED;
        }
    }

    protected Log getLog() {
        return log;
    }

    private void endRequest() {
        if (this.getErrorState().isError()) {
            this.inputBuffer.setSwallowInput(false);
        } else {
            this.checkExpectationAndResponseStatus();
        }

        if (this.getErrorState().isIoAllowed()) {
            try {
                this.inputBuffer.endRequest();
            } catch (IOException var4) {
                this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, var4);
            } catch (Throwable var5) {
                ExceptionUtils.handleThrowable(var5);
                this.response.setStatus(500);
                this.setErrorState(ErrorState.CLOSE_NOW, var5);
                log.error(sm.getString("http11processor.request.finish"), var5);
            }
        }

        if (this.getErrorState().isIoAllowed()) {
            try {
                this.action(ActionCode.COMMIT, (Object)null);
                this.outputBuffer.end();
            } catch (IOException var2) {
                this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, var2);
            } catch (Throwable var3) {
                ExceptionUtils.handleThrowable(var3);
                this.setErrorState(ErrorState.CLOSE_NOW, var3);
                log.error(sm.getString("http11processor.response.finish"), var3);
            }
        }

    }

    protected final void finishResponse() throws IOException {
        this.outputBuffer.end();
    }

    protected final void ack() {
        this.ack(ContinueResponseTiming.ALWAYS);
    }

    protected final void ack(ContinueResponseTiming continueResponseTiming) {
        if ((continueResponseTiming == ContinueResponseTiming.ALWAYS || continueResponseTiming == this.protocol.getContinueResponseTimingInternal()) && !this.response.isCommitted() && this.request.hasExpectation()) {
            this.inputBuffer.setSwallowInput(true);

            try {
                this.outputBuffer.sendAck();
            } catch (IOException var3) {
                this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, var3);
            }
        }

    }

    protected final void flush() throws IOException {
        this.outputBuffer.flush();
    }

    protected final int available(boolean doRead) {
        return this.inputBuffer.available(doRead);
    }

    protected final void setRequestBody(ByteChunk body) {
        InputFilter savedBody = new SavedRequestInputFilter(body);
        Http11InputBuffer internalBuffer = (Http11InputBuffer)this.request.getInputBuffer();
        internalBuffer.addActiveFilter(savedBody);
    }

    protected final void setSwallowResponse() {
        this.outputBuffer.responseFinished = true;
    }

    protected final void disableSwallowRequest() {
        this.inputBuffer.setSwallowInput(false);
    }

    protected final void sslReHandShake() throws IOException {
        if (this.sslSupport != null) {
            InputFilter[] inputFilters = this.inputBuffer.getFilters();
            ((BufferedInputFilter)inputFilters[3]).setLimit(this.protocol.getMaxSavePostSize());
            this.inputBuffer.addActiveFilter(inputFilters[3]);
            this.socketWrapper.doClientAuth(this.sslSupport);

            try {
                Object sslO = this.sslSupport.getPeerCertificateChain();
                if (sslO != null) {
                    this.request.setAttribute("javax.servlet.request.X509Certificate", sslO);
                }
            } catch (IOException var3) {
                log.warn(sm.getString("http11processor.socket.ssl"), var3);
            }
        }

    }

    protected final boolean isRequestBodyFullyRead() {
        return this.inputBuffer.isFinished();
    }

    protected final void registerReadInterest() {
        this.socketWrapper.registerReadInterest();
    }

    protected final boolean isReadyForWrite() {
        return this.outputBuffer.isReady();
    }

    public UpgradeToken getUpgradeToken() {
        return this.upgradeToken;
    }

    protected final void doHttpUpgrade(UpgradeToken upgradeToken) {
        this.upgradeToken = upgradeToken;
        this.outputBuffer.responseFinished = true;
    }

    public ByteBuffer getLeftoverInput() {
        return this.inputBuffer.getLeftover();
    }

    public boolean isUpgrade() {
        return this.upgradeToken != null;
    }

    protected boolean isTrailerFieldsReady() {
        return this.inputBuffer.isChunking() ? this.inputBuffer.isFinished() : true;
    }

    protected boolean isTrailerFieldsSupported() {
        if (!this.http11) {
            return false;
        } else {
            return !this.response.isCommitted() ? true : this.outputBuffer.isChunking();
        }
    }

    private SendfileState processSendfile(SocketWrapperBase<?> socketWrapper) {
        this.openSocket = this.keepAlive;
        SendfileState result = SendfileState.DONE;
        if (this.sendfileData != null && !this.getErrorState().isError()) {
            if (this.keepAlive) {
                if (this.available(false) == 0) {
                    this.sendfileData.keepAliveState = SendfileKeepAliveState.OPEN;
                } else {
                    this.sendfileData.keepAliveState = SendfileKeepAliveState.PIPELINED;
                }
            } else {
                this.sendfileData.keepAliveState = SendfileKeepAliveState.NONE;
            }

            result = socketWrapper.processSendfile(this.sendfileData);
            switch(result) {
                case ERROR:
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("http11processor.sendfile.error"));
                    }

                    this.setErrorState(ErrorState.CLOSE_CONNECTION_NOW, (Throwable)null);
                default:
                    this.sendfileData = null;
            }
        }

        return result;
    }

    public final void recycle() {
        this.getAdapter().checkRecycled(this.request, this.response);
        super.recycle();
        this.inputBuffer.recycle();
        this.outputBuffer.recycle();
        this.upgradeToken = null;
        this.socketWrapper = null;
        this.sendfileData = null;
        this.sslSupport = null;
    }

    public void pause() {
    }
}
