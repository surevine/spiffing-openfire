package com.surevine.spiffing.openfire;

import com.surevine.spiffing.*;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.jivesoftware.openfire.PacketRouter;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.*;

import java.io.File;
import java.io.StringReader;
import java.util.*;

public class PluginMain implements Plugin, PacketInterceptor {
    private static final Logger Log = LoggerFactory.getLogger(PluginMain.class);
    PluginManager pluginManager;
    File pluginPath;
    Site site;
    LinkedHashMap<JID,LinkedHashMap<String,Clearance>> clearance_cache;
    LinkedHashMap<String,Label> label_cache;
    LinkedHashMap<String,Clearance> serverClearance;
    Label defaultLabel;
    LinkedHashMap<String,Clearance> defaultUserClearance;
    LinkedHashMap<String,Clearance> defaultPeerClearance;
    CatalogueHandler catHandler0;
    CatalogueHandler catHandler2;
    ClearanceHandler clrHandler;
    long policiesLoaded = 0;
    PacketRouter router = null;

    // Property names
    static String PROP_POLICY_FILES = "spiffing.policies";
    static String PROP_LABEL_CATALOGUE = "spiffing.label.catalogue";
    static String PROP_SERVER_CLEARANCE = "spiffing.clearance.server";
    static String PROP_DEFUSER_CLEARANCE = "spiffing.clearance.user.default";
    static String PROP_DEFPEER_CLEARANCE = "spiffing.clearance.peer.default";
    static String PROP_DEFLABEL = "spiffing.label.default";
    static String PROP_PEER_PREFIX = "spiffing.clearance.peer.";
    static String PROP_USER_POL_PREFIX = "spiffing.policy.user.";
    static String PROP_PEER_POL_PREFIX = "spiffing.policy.peer.";

    // Plugin bits.

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        pluginManager = manager;
        pluginPath = pluginDirectory;
        InterceptorManager.getInstance().addInterceptor(this);
        clearance_cache = new LinkedHashMap<JID,LinkedHashMap<String,Clearance>>(16, (float)0.75, true) {
            protected boolean removeEldestEntry(Map.Entry<JID,LinkedHashMap<String,Clearance>> eldest) {
                if (size() > 100) {
                    try {
                        for (Map.Entry<String,Clearance> cl : eldest.getValue().entrySet()) cl.getValue().close();
                    } catch (Exception e) {
                        // Maybe leak?
                    }
                    return true;
                }
                return false;
            }
        };
        label_cache = new LinkedHashMap<String,Label>(16, (float)0.75, true) {
            protected boolean removeEldestEntry(Map.Entry<String,Label> eldest) {
                if (size() > 100) {
                    try {
                        eldest.getValue().close();
                    } catch (Exception e) {
                        // Maybe leak?
                    }
                    return true;
                }
                return false;
            }
        };
        router = XMPPServer.getInstance().getPacketRouter();
        try {
            System.out.println("Spiffing XEP-0258 module loading...");
            Log.info("Spiffing XEP-0258 module loading...");
            System.setProperty("java.library.path", "/tmp:" + System.getProperty("java.library.path"));
            System.out.println("... searching for native code in " + System.getProperty("java.library.path"));
            System.out.println("... searching for Java code in " + System.getProperty("java.class.path"));
            Log.info("Native code search path: " + System.getProperty("java.library.path"));
            site = new Site();
            System.out.println("... Loaded OK");
            Log.info("Spiffing XEP-0258 module loaded");
            for (String policyFile : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_POLICY_FILES))) {
                Spif s = site.load(policyFile);
                Log.info("Loaded SPIF " + s.name());
                ++policiesLoaded;
            }
            for (String lablob : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_LABEL_CATALOGUE))) {
                Label l = getLabel(lablob);
                Log.info("Loaded label catalogue entry " + l.displayMarking());
            }
            serverClearance = new LinkedHashMap<>();
            for (String serverCl : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_SERVER_CLEARANCE))) {
                Clearance cl = new Clearance(serverCl);
                serverClearance.put(cl.policy().policy_id(), cl);
                Log.info("Loaded server clearance " + cl.displayMarking());
            }
            defaultUserClearance = new LinkedHashMap<>();
            for (String serverCl : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_DEFUSER_CLEARANCE))) {
                Clearance cl = new Clearance(serverCl);
                defaultUserClearance.put(cl.policy().policy_id(), cl);
                Log.info("Loaded default user clearance " + cl.displayMarking());
            }
            defaultPeerClearance = new LinkedHashMap<>();
            for (String serverCl : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_DEFPEER_CLEARANCE))) {
                Clearance cl = new Clearance(serverCl);
                defaultPeerClearance.put(cl.policy().policy_id(), cl);
                Log.info("Loaded default peer clearance " + cl.displayMarking());
            }
            String deflablob = JiveGlobals.getProperty(PROP_DEFLABEL);
            if (deflablob != null) {
                defaultLabel = new Label(deflablob);
                Log.info("Default label is " + defaultLabel.displayMarking());
            }
        } catch (SIOException e) {
            Log.warn("Spiffing failed to initialize properly", e);
            return;
        }
        this.catHandler2 = new CatalogueHandler(this, true);
        XMPPServer.getInstance().getIQRouter().addHandler(this.catHandler2);
        this.catHandler0 = new CatalogueHandler(this, false);
        XMPPServer.getInstance().getIQRouter().addHandler(this.catHandler0);
        this.clrHandler = new ClearanceHandler(this);
        XMPPServer.getInstance().getIQRouter().addHandler(this.clrHandler);
        XMPPServer.getInstance().getIQDiscoInfoHandler().addServerFeature("urn:xmpp:sec-label:0");
        XMPPServer.getInstance().getIQDiscoInfoHandler().addServerFeature("urn:xmpp:sec-label:catalog:0");
        XMPPServer.getInstance().getIQDiscoInfoHandler().addServerFeature("urn:xmpp:sec-label:catalog:2");
    }

    @Override
    public void destroyPlugin() {
        InterceptorManager.getInstance().removeInterceptor(this);
        XMPPServer.getInstance().getIQRouter().removeHandler(this.catHandler2);
        this.catHandler2 = null;
        XMPPServer.getInstance().getIQRouter().removeHandler(this.catHandler0);
        this.catHandler0 = null;
        XMPPServer.getInstance().getIQRouter().removeHandler(this.clrHandler);
        this.clrHandler = null;
        // Clear label/clearance cache
        // Destroy labels and clearances.
        try {
            site.dispose();
            site = null;
        } catch (SIOException e) {
            Log.warn("Spiffing failed to shutdown properly", e);
        }
    }

    // PacketInterceptor bits.

    @Override
    public void interceptPacket(Packet packet, Session session, boolean incoming, boolean processed) throws PacketRejectedException {
        Log.debug("Packet intercept: " + packet.toString());
        if (!(packet instanceof Message)) {
            Log.debug("Not a message, tossing.");
            return;
        }
        if (policiesLoaded == 0) {
            return;
        }
        try {
            Label label = null;
            boolean rewritten = false;
            boolean need_rewrite = false;
            PacketExtension secLabel = packet.getExtension("securitylabel", "urn:xmpp:sec-label:0");
            if (secLabel != null) {
                Element labelElement = (Element) secLabel.getElement().element("label").elements().get(0);
                // What do we have?
                if (labelElement.getNamespaceURI().equals("urn:xmpp:sec-label:ess:0")) {
                    // ESS Label, base64 encoded.
                    String labelstr = labelElement.getStringValue();
                    label = getLabel(labelstr);
                    Log.debug("Got label of " + label.displayMarking());
                } else if (labelElement.getNamespaceURI().equals("urn:nato:stanag:4774:confidentialitymetadatalabel:1:0")) {
                    String labelstr = labelElement.asXML();
                    label = getLabel(labelstr);
                    Log.debug("Got a NATO label " + label.displayMarking());
                }
            }
            Set<String> target_policies = getTargetPolicies(packet.getTo());
            if (label == null) {
                label = defaultLabel;
                Log.debug("Label is default");
                need_rewrite = true;
            }
            Log.debug("Server");
            try (Label equiv = doACDF(serverClearance, label)) {
                // If policy mismatch occurs here, we'll ignore it.
            }
            Log.debug("Sender");
            try (Label equiv = doACDF(getClearance(packet.getFrom()), label)) {
                // Likewise here, although that'd be pretty weird.
            }
            Log.debug("Recipient");
            try (Label equiv = doACDF(getClearance(packet.getTo()), label)) {
                if (equiv != null) {
                    // Is this in the target policy?
                    if (target_policies.contains(equiv.policy().policy_id())) {
                        // Rewrite required; we'll rewrite the label into the target policy and display marking.
                        Log.debug("Rewriting recipient label to " + equiv.displayMarking());
                        rewriteExtension(packet, equiv);
                        rewritten = true;
                    }
                }
            }
            if (!rewritten) {
                if (!need_rewrite) {
                    if (!target_policies.contains(label.policy().policy_id())) {
                        need_rewrite = true;
                    } else {
                        Element displayMarking = secLabel.getElement().element("displaymarking");
                        if (displayMarking == null) {
                            need_rewrite = true;
                        } else {
                            String dm = displayMarking.getStringValue();
                            String fgcol = displayMarking.attributeValue("fgcolor");

                            if (!(fgcol.equals(label.fgColour()) && dm.equals(label.displayMarking()))) {
                                Log.debug("Needs rewrite anyway");
                                need_rewrite = true;
                            }
                        }
                    }
                }
                if (!target_policies.contains(label.policy().policy_id())) {
                    for (String policy_id : target_policies) {
                        Spif policy = Site.site().spif(policy_id);
                        try (Label equiv = label.encrypt(policy)) {
                            rewriteExtension(packet, equiv);
                            need_rewrite = false;
                            rewritten = true;
                            break;
                        }
                    }
                }
                if (need_rewrite) {
                    Log.debug("Rewriting label");
                    rewriteExtension(packet, label);
                }
            }
        } catch (Exception e) {
            Log.info("ACDF rejection: ", e);
            if (incoming) {
                Message msg = (Message)packet;
                Message error = new Message(); // Don't copy; it might introduce an invalid label.
                error.setTo(msg.getFrom());
                error.setFrom(msg.getTo());
                error.setID(msg.getID());
                error.setError(PacketError.Condition.forbidden);
                error.setType(Message.Type.error);
                XMPPServer.getInstance().getMessageRouter().route(error);
            }
            throw new PacketRejectedException(e);
        }
    }

    // XEP-0258 support

    public LinkedHashMap<String,Clearance> getClearance(JID entity) {
        Log.debug("Locating clearance for " + entity);
        if (XMPPServer.getInstance().isLocal(entity)) {
            // Local user
            LinkedHashMap<String,Clearance> usercl = clearance_cache.get(entity);
            if (usercl == null) {
                usercl = new LinkedHashMap<>();
                User user;
                try {
                    user = UserManager.getInstance().getUser(entity.getNode());
                } catch(UserNotFoundException e) {
                    return defaultUserClearance;
                }
                for (String serverCl : StringUtils.stringToCollection(user.getProperties().get("spiffing.clearance"))) {
                    try {
                        Clearance cl = new Clearance(serverCl);
                        usercl.put(cl.policy().policy_id(), cl);
                        Log.info("Loaded user clearance " + cl.displayMarking());
                    } catch (SIOException e) {
                        Log.warn("User clearance for " + entity + " failed to load:", e);
                    }
                }
                if (usercl.isEmpty()) {
                    Log.debug("Using default user clearance");
                    return defaultUserClearance;
                }
                clearance_cache.put(entity, usercl);
            }
            return usercl;
        } else {
            // Local user
            LinkedHashMap<String,Clearance> peercl = clearance_cache.get(entity);
            if (peercl == null) {
                peercl = new LinkedHashMap<>();
                for (String serverCl : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_PEER_PREFIX + entity.getDomain()))) {
                    try {
                        Clearance cl = new Clearance(serverCl);
                        peercl.put(cl.policy().policy_id(), cl);
                        Log.info("Loaded peer clearance " + cl.displayMarking());
                    } catch (SIOException e) {
                        Log.warn("Peer clearance for " + entity + " failed to load:", e);
                    }

                }
                if (peercl.isEmpty()) {
                    Log.debug("Using default peer clearance");
                    return defaultPeerClearance;
                }
                clearance_cache.put(entity, peercl);
            }
            return peercl;
        }
    }

    public Label getLabel(String lablob) throws SIOException {
        Label l = label_cache.get(lablob);
        if (l == null) {
            l = new Label(lablob);
            if (!l.valid()) {
                throw new SIOException("Label not valid");
            }
            label_cache.put(lablob, l);
        }
        return l;
    }

    public Label doACDF(LinkedHashMap<String,Clearance> cls, Label l) throws PacketRejectedException {
        try {
            // Find best policy match, if any:
            if (cls.containsKey(l.policy().policy_id())) {
                // Have a matching clearance, just use that.
                if (!cls.get(l.policy().policy_id()).dominates(l)) {
                    throw new PacketRejectedException("ACDF failure (policy match) [" + cls.get(l.policy().policy_id()).displayMarking() + "] << [" + l.displayMarking() + "]");
                }
                return null;
            } else {
                for (Map.Entry<String, Clearance> entry : cls.entrySet()) {
                    try {
                        Spif clpolicy = entry.getValue().policy();
                        try (Label equiv = l.encrypt(clpolicy)) {
                            if (entry.getValue().dominates(equiv)) {
                                return equiv;
                            } else {
                                throw new PacketRejectedException("ACDF failure (equiv fails)");
                            }
                        } catch (SIOException e) {
                            // Ignore; missing encrypt or label fails to dominate.
                        }
                    } catch (Exception e) {
                        throw new PacketRejectedException(e);
                    }
                }
            }
            throw new PacketRejectedException("ACDF failure (no equivs available)");
        } catch (SIOException e) {
            throw new PacketRejectedException(e);
        }
    }

    Set<String> getTargetPolicies(JID entity) {
        Set<String> pols = new HashSet<>();
        if (XMPPServer.getInstance().isLocal(entity)) {
            pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_USER_POL_PREFIX + entity.getNode())));
        } else {
            pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_PEER_POL_PREFIX + entity.getDomain())));
        }
        if (pols.isEmpty()) {
            pols.addAll(getClearance(entity).keySet());
        }
        return pols;
    }

    private void rewriteExtension(Packet packet, Label label) throws PacketRejectedException {
        try {
            packet.deleteExtension("securitylabel", "urn:xmpp:sec-label:0");
            PacketExtension ext = new PacketExtension("securitylabel", "urn:xmpp:sec-label:0");
            populate258(ext.getElement(), label);
            packet.addExtension(ext);
        } catch (Exception e) {
            throw new PacketRejectedException(e);
        }
    }

    public void populate258(Element el, Label label) throws SIOException {
        Element dm = el.addElement("displaymarking");
        if (label.bgColour() != null) {
            dm.addAttribute("bgcolor", label.bgColour());
        }
        if (label.fgColour() != null) {
            dm.addAttribute("fgcolor", label.fgColour());
        }
        dm.addText(label.displayMarking());

        Element container = el.addElement("label");
        SAXReader reader = new SAXReader();
        reader.setEncoding("UTF-8");
        try {
            Element nato = reader.read(new StringReader(label.toNATOXML())).getRootElement();

            container.add(nato.createCopy());
        } catch(DocumentException e) {
            Log.warn("Encoded label does not parse: ", e);
            throw new SIOException("Label encoding error");
        }
    }

    // Catalogue support

    public Collection<Label> catalogue() {
        return label_cache.values();
    }
}
