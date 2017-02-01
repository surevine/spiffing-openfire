package com.surevine.spiffing.openfire;

import com.surevine.spiffing.Clearance;
import com.surevine.spiffing.SIOException;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.handler.IQHandler;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.PacketError;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by dwd on 09/02/16.
 */
public class ClearanceHandler extends IQHandler {
    private static final Logger Log = LoggerFactory.getLogger(ClearanceHandler.class);
    PluginMain plugin;
    IQHandlerInfo info;
    static String NS_CLEARANCE = "http://surevine.com/spiffing";

    public ClearanceHandler(PluginMain plugin) {
        super("Clearance Handler");
        this.plugin = plugin;
        this.info = new IQHandlerInfo("clearance", NS_CLEARANCE);

    }

    @Override
    public IQ handleIQ(IQ packet) throws UnauthorizedException {
        IQ reply = IQ.createResultIQ(packet);
        Element req = packet.getChildElement();
        if (req.getName().equals("clearance")) {
            Element catalog = reply.setChildElement("clearance", NS_CLEARANCE);
            LinkedHashMap<String, Clearance> target_clearance = this.plugin.getClearance(packet.getFrom());
            for (Map.Entry<String, Clearance> e : target_clearance.entrySet()) {
                SAXReader reader = new SAXReader();
                reader.setEncoding("UTF-8");
                try {
                    Element item = catalog.addElement("item");
                    item.addAttribute("policy-id", e.getKey());
                    item.addAttribute("policy", e.getValue().policy().name());
                    Element nato = reader.read(new StringReader(e.getValue().toNATOXML())).getRootElement();
                    item.add(nato.createCopy());
                } catch (SIOException ex) {
                    Log.warn("Internal spiffing error: ", ex);
                    reply.setError(PacketError.Condition.internal_server_error);
                } catch (DocumentException ex) {
                    Log.warn("Encoded label does not parse: ", ex);
                    reply.setError(PacketError.Condition.internal_server_error);
                }
            }
        } else { // TODO * Assume policy
            Element policies = reply.setChildElement("policy", NS_CLEARANCE);
            try {
                for (String policyFile : StringUtils.stringToCollection(JiveGlobals.getProperty(PluginMain.PROP_POLICY_FILES))) {
                    SAXReader reader = new SAXReader();
                    reader.setEncoding("UTF-8");
                    Element nato = reader.read(new FileReader(policyFile)).getRootElement();
                    policies.add(nato.createCopy());
                }
            } catch (IOException e) {
                Log.warn("Failed to read policy file: ", e);
                reply.setError(PacketError.Condition.internal_server_error);
            } catch (DocumentException e) {
                Log.warn("Failed to parse policy file: ", e);
                reply.setError(PacketError.Condition.internal_server_error);
            }
        }
        return reply;
    }

    @Override
    public IQHandlerInfo getInfo() {
        return info;
    }
}
