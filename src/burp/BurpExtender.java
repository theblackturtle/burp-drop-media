package burp;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IHttpListener {
    public static String name = "Drop Media";
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            if (message.getResponse() == null) {
                return;
            }
            IResponseInfo details = helpers.analyzeResponse(message.getResponse());
            if (details.getInferredMimeType().toLowerCase().equals("video") || details.getStatedMimeType().toLowerCase().equals("video")) {
                dropMediaRequest(message);
            }
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(name);
        callbacks.registerHttpListener(this);
    }

    private void dropMediaRequest(IHttpRequestResponse message) {
        IResponseInfo analyzedResponse = helpers.analyzeResponse(message.getResponse());
        ByteArrayOutputStream rebuildBody = new ByteArrayOutputStream();

        try {
            rebuildBody.write(Arrays.copyOfRange(message.getResponse(), 0, analyzedResponse.getBodyOffset()));
            rebuildBody.write("Video Body".getBytes());
            message.setResponse(rebuildBody.toByteArray());
        } catch (Exception ex) {
            callbacks.printOutput("Drop Media extension: " + ex.toString());
        }
    }

    @Override
    public void extensionUnloaded() {
        callbacks.printOutput("Extension Unloaded");
    }
}