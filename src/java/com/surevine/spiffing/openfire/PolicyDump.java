package com.surevine.spiffing.openfire;

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
import org.xmpp.packet.PacketError;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Created by dwd on 01/02/17.
 */
public class PolicyDump extends IQHandler {
    private PluginMain plugin;
    private IQHandlerInfo info;
    static String NS = "http://surevine.com/spiffing";
    private static final Logger Log = LoggerFactory.getLogger(ClearanceHandler.class);

    public PolicyDump(PluginMain plugin) {
        super("Policy Dump Handler");
        this.plugin = plugin;
        this.info = new IQHandlerInfo("policy", NS);
    }

    @Override
    public IQ handleIQ(IQ packet) throws UnauthorizedException {
        IQ reply = IQ.createResultIQ(packet);
        Element policies = reply.setChildElement("policy", NS);
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
        return reply;
    }

    @Override
    public IQHandlerInfo getInfo() {
        return null;
    }
}
