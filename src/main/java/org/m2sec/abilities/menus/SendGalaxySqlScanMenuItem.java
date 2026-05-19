package org.m2sec.abilities.menus;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import org.m2sec.abilities.HttpHookHandler;
import org.m2sec.core.common.Config;
import org.m2sec.core.common.Constants;
import org.m2sec.core.common.SwingTools;
import org.m2sec.panels.galaxysql.GalaxySqlPanel;

public class SendGalaxySqlScanMenuItem extends IItem {

    public SendGalaxySqlScanMenuItem(MontoyaApi api, Config config) {
        super(api, config);
    }

    @Override
    public String displayName() {
        return "send galaxySql scan";
    }

    @Override
    public boolean isDisplay(ContextMenuEvent event) {
        return event.messageEditorRequestResponse().isPresent()
            && event.messageEditorRequestResponse().get().selectionContext().equals(MessageEditorHttpRequestResponse.SelectionContext.REQUEST)
            && config.getOption().isHookStart()
            && HttpHookHandler.hooker != null;
    }

    @Override
    @SuppressWarnings("OptionalGetWithoutIsPresent")
    public void action(ContextMenuEvent event) {
        MessageEditorHttpRequestResponse messageEditorHttpRequestResponse = event.messageEditorRequestResponse().get();
        HttpRequest request = messageEditorHttpRequestResponse.requestResponse().request();
        HttpResponse response = messageEditorHttpRequestResponse.requestResponse().response();
        
        ToolType toolFlag = ToolType.PROXY;
        if (event.isFromTool(ToolType.REPEATER)) {
            toolFlag = ToolType.REPEATER;
        }

        if (!request.hasHeader(Constants.HTTP_HEADER_HOOK_HEADER_KEY)) {
            SwingTools.showInfoDialog(api, "The request is not decrypted.");
            return;
        }
        
        if (GalaxySqlPanel.getInstance() != null) {
            GalaxySqlPanel.getInstance().checkVul(request, response, toolFlag);
        } else {
            SwingTools.showInfoDialog(api, "GalaxySqlPanel is not initialized.");
        }
    }
}
