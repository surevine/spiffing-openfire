package com.surevine.spiffing.openfire;

import com.surevine.spiffing.Clearance;
import com.surevine.spiffing.SIOException;
import org.dom4j.Element;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.handler.IQHandler;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by dwd on 09/02/16.
 */
public class ClearanceHandler extends IQHandler {
    PluginMain plugin;
    IQHandlerInfo info;
    static String NS_CLEARANCE = "http://surevine.com/spiffing/clearance-query";

    public ClearanceHandler(PluginMain plugin) {
        super("Clearance Handler");
        this.plugin = plugin;
        this.info = new IQHandlerInfo("clearance", NS_CLEARANCE);

    }

    @Override
    public IQ handleIQ(IQ packet) throws UnauthorizedException {
        IQ reply = IQ.createResultIQ(packet);
        Element catalog = reply.setChildElement("clearance", NS_CLEARANCE);
        Element req = packet.getChildElement();
        LinkedHashMap<String,Clearance> target_clearance = this.plugin.getClearance(new JID(req.attributeValue("target")));
        for (Map.Entry<String,Clearance> e : target_clearance.entrySet()) {
            try {
                String enc = e.getValue().toESSBase64();
                Element item = catalog.addElement("item");
                item.addAttribute("policy", e.getKey());
                item.setText(enc);
            } catch (SIOException ex) {
                // ...
            }
        }
        return reply;
    }

    @Override
    public IQHandlerInfo getInfo() {
        return info;
    }
}
