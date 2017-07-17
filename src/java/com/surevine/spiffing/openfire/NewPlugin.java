package com.surevine.spiffing.openfire;

import com.surevine.spiffing.*;
import com.surevine.spiffing.Clearance;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.labelling.*;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.io.File;
import java.io.StringReader;
import java.util.*;

/**
 * Created by dwd on 20/03/17.
 */
public class NewPlugin extends AbstractACDF implements Plugin {
    private static final Logger Log = LoggerFactory.getLogger(NewPlugin.class);
    private PluginManager pluginManager;
    private File pluginPath;
    private Site site;

    static String PROP_POLICY_FILES = "spiffing.policies";
    static String PROP_DEFLABEL = "spiffing.label.default";
    static String PROP_LABEL_CATALOGUE = "spiffing.label.catalogue";
    static String PROP_USER_POL_PREFIX = "spiffing.policy.user.";
    static String PROP_PEER_POL_PREFIX = "spiffing.policy.peer.";

    private LinkedHashMap<String,Label> label_cache;
    private Label defaultLabel;

    private ClearanceHandler clrHandler = null;
    private CatalogueHandler catHandler0 = null;
    private CatalogueHandler catHandler2 = null;

    public NewPlugin() {
        super();
    }

    @Override
    public void initializePlugin(PluginManager manager, File pluginDirectory) {
        this.pluginManager = manager;
        this.pluginPath = pluginDirectory;
        label_cache = new LinkedHashMap<String, Label>(16, (float) 0.75, true) {
            protected boolean removeEldestEntry(Map.Entry<String, Label> eldest) {
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

        int policiesLoaded = 0;
        try {
            Log.info("Spiffing labelling plugin loading...");
            this.site = new Site();
            for (String policyFile : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_POLICY_FILES))) {
                Log.info("Policy file: '" + policyFile + "'");
                Spif s = site.load(policyFile);
                Log.info("Loaded SPIF " + s.name());
                ++policiesLoaded;
            }
            if (policiesLoaded > 0) {
                for (String lablob : StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_LABEL_CATALOGUE))) {
                    Label l = getLabel(lablob);
                    Log.info("Loaded label catalogue entry " + l.displayMarking());
                }
                String deflablob = JiveGlobals.getProperty(PROP_DEFLABEL);
                if (deflablob != null) {
                    defaultLabel = new Label(deflablob);
                    Log.info("Default label is " + defaultLabel.displayMarking());
                }
            }
        } catch (SIOException e) {
            Log.warn("Couldn't setup Spiffing: ", e);
        }
        if (policiesLoaded > 0) {
            this.catHandler2 = new CatalogueHandler(this, true);
            XMPPServer.getInstance().getIQRouter().addHandler(this.catHandler2);
            this.catHandler0 = new CatalogueHandler(this, false);
            XMPPServer.getInstance().getIQRouter().addHandler(this.catHandler0);
            this.clrHandler = new ClearanceHandler(this);
            XMPPServer.getInstance().getIQRouter().addHandler(this.clrHandler);
            XMPPServer.getInstance().getIQDiscoInfoHandler().addServerFeature("urn:xmpp:sec-label:catalog:0");
            XMPPServer.getInstance().getIQDiscoInfoHandler().addServerFeature("urn:xmpp:sec-label:catalog:2");
            XMPPServer.getInstance().setAccessControlDecisionFunction(this);
        }
    }

    private Label getLabel(String lablob) throws SIOException {
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

    private Label getLabel(Element labelElement) throws SIOException {
        Label label = null;
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
        } else {
            throw new SIOException("No idea what " + labelElement.getNamespaceURI() + " means.");
        }
        return label;
    }

    private Label getLabel(SecurityLabel securityLabel) throws SIOException {
        return securityLabel == null ? getDefaultLabel() : getLabel(securityLabel.getLabel());
    }

    @Override
    public void destroyPlugin() {
        XMPPServer.getInstance().setAccessControlDecisionFunction(null);
        if (this.catHandler2 != null) {
            XMPPServer.getInstance().getIQRouter().removeHandler(this.catHandler2);
            this.catHandler2 = null;
        }
        if (this.catHandler0 != null) {
            XMPPServer.getInstance().getIQRouter().removeHandler(this.catHandler0);
            this.catHandler0 = null;
        }
        if (this.clrHandler != null) {
            XMPPServer.getInstance().getIQRouter().removeHandler(this.clrHandler);
            this.clrHandler = null;
        }
        XMPPServer.getInstance().getIQDiscoInfoHandler().removeServerFeature("urn:xmpp:sec-label:catalog:0");
        XMPPServer.getInstance().getIQDiscoInfoHandler().removeServerFeature("urn:xmpp:sec-label:catalog:2");
        if (label_cache != null) {
            for (String str : label_cache.keySet()) {
                try {
                    Label l = label_cache.remove(str);
                    l.close();
                } catch (Exception ex) {
                    Log.warn("While freeing Label: ", ex);
                }
            }
            label_cache = null;
        }
        if (defaultLabel != null) {
            defaultLabel.dispose();
            defaultLabel = null;
        }
        if (site != null) {
            try {
                site.dispose();
                site = null;
            } catch (SIOException e) {
                Log.warn("Spiffing failed to shutdown properly", e);
            }
        }
    }

    @Override
    public SecurityLabel check(String clearanceString, SecurityLabel label, JID rewrite) {
        LinkedHashMap<String, Clearance> clearances = getSpiffingClearance(clearanceString);
        try {
            Label l = getLabel(label);
            Label result = check(clearances, l, rewrite);
            if (result != null) {
                return rewrite(result);
            }
        } catch(SIOException e) {
            Log.warn("Exception during input or rewrite: ", e);
            throw new SecurityLabelException("ACDF Failure: " + e.getMessage());
        } finally {
            dispose(clearances);
        }
        return null;
    }

    public Label check(LinkedHashMap<String,Clearance> clearances, Label l, JID rewrite) {
        try {
            if (!l.valid()) {
                throw new SIOException("Label not valid");
            }

            Label equiv = null;
            try {
                // Find best policy match, if any:
                if (clearances.containsKey(l.policy().policy_id())) {
                    // Have a matching clearance, just use that.
                    if (!clearances.get(l.policy().policy_id()).dominates(l)) {
                        throw new SecurityLabelException("ACDF failure (policy match) [" + clearances.get(l.policy().policy_id()).displayMarking() + "] << [" + l.displayMarking() + "]");
                    }
                    equiv = l;
                } else {
                    for (Map.Entry<String, Clearance> entry : clearances.entrySet()) {
                        try {
                            Spif clpolicy = entry.getValue().policy();
                            try {
                                equiv = l.encrypt(clpolicy);
                                String s = equiv.toNATOXML();
                                if (!label_cache.containsKey(s)) {
                                    label_cache.put(equiv.toNATOXML(), equiv);
                                } else {
                                    equiv.dispose();
                                    equiv = label_cache.get(s);
                                }
                                if (!entry.getValue().dominates(equiv)) {
                                    throw new SecurityLabelException("ACDF failure (equiv fails)");
                                }
                            } catch (SIOException e) {
                                // Ignore; missing encrypt or label fails to dominate.
                            }
                        } catch (SIOException e) {
                            throw new SecurityLabelException("ACDF failure (exception: " + e.getMessage() + ")");
                        }
                    }
                }
                if (equiv == null) {
                    throw new SecurityLabelException("ACDF failure (no equivs available)");
                }
            } catch (SIOException e) {
                throw new SecurityLabelException("ACDF failure (exception: " + e.getMessage() + ")");
            }

            if (rewrite != null) {
                Set<String> pols = new HashSet<>();
                if (XMPPServer.getInstance().isLocal(rewrite)) {
                    pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_USER_POL_PREFIX + rewrite.getNode())));
                } else {
                    pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_PEER_POL_PREFIX + rewrite.getDomain())));
                }
                if (pols.isEmpty()) {
                    pols.addAll(clearances.keySet());
                }
                if (equiv != null) {
                    if (pols.contains(equiv.policy().policy_id())) {
                        // This one.
                        return equiv;
                    }
                }
                if (pols.contains(l.policy().policy_id())) {
                    return l;
                }
                for (String policy_id : pols) {
                    try {
                        equiv = l.encrypt(Site.site().spif(policy_id));
                        String s = equiv.toNATOXML();
                        if (!label_cache.containsKey(s)) {
                            label_cache.put(equiv.toNATOXML(), equiv);
                        } else {
                            equiv.dispose();
                            equiv = label_cache.get(s);
                        }
                        return equiv;
                    } catch (SIOException e) {
                        // Ignore; missing encrypt.
                    }
                }
                throw new SecurityLabelException("Couldn't not rewrite label to known policy");
            }
            return null;
        } catch (SIOException e) {
            Log.warn("Malformed input label: ", e);
            throw new SecurityLabelException("Malformed input label: " + e.getMessage());
        }
    }

    @Override
    public SecurityLabel valid(SecurityLabel label, boolean rewrite) {
        try {
            Label l = getLabel(label);
            if (!l.valid()) {
                throw new SecurityLabelException("Label is not valid");
            }
            if (rewrite) {
                return rewrite(l);
            }
            return null;
        } catch (SIOException e) {
            throw new SecurityLabelException("Label is not valid: " + e);
        }
    }

    LinkedHashMap<String,Clearance> getSpiffingClearance(JID entity) {
        return getSpiffingClearance(getClearance(entity));
    }

    LinkedHashMap<String, Clearance> getSpiffingClearance(String clearanceString) {
        LinkedHashMap<String, Clearance> clearances = new LinkedHashMap<>();
        for (String clearance : StringUtils.stringToCollection(clearanceString)) {
            try {
                Clearance clr = new Clearance(clearance);
                clearances.put(clr.policy().policy_id(), clr);
            } catch (SIOException e) {
                Log.warn("Bad Clearance in clearance string: ", e);
            }
        }
        return clearances;
    }

    private void dispose(LinkedHashMap<String, Clearance> clearances) {
        for (String policy : clearances.keySet()) {
            try {
                Clearance c = clearances.get(policy);
                c.close();
            } catch (Exception ex) {
                Log.warn("While freeing Clearance: ", ex);
            }
        }
        clearances.clear();
    }

    Label getEquiv(JID entity, Label input, LinkedHashMap<String,Clearance> clearances) {
        try {
            Set<String> pols = new HashSet<>();
            if (XMPPServer.getInstance().isLocal(entity)) {
                pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_USER_POL_PREFIX + entity.getNode())));
            } else {
                pols.addAll(StringUtils.stringToCollection(JiveGlobals.getProperty(PROP_PEER_POL_PREFIX + entity.getDomain())));
            }
            if (pols.isEmpty()) {
                pols.addAll(clearances.keySet());
            }
            if (pols.contains(input.policy().policy_id())) {
                return input;
            }
            for (String policy_id : pols) {
                try {
                    Label equiv = input.encrypt(Site.site().spif(policy_id));
                    String s = equiv.toNATOXML();
                    if (!label_cache.containsKey(s)) {
                        label_cache.put(equiv.toNATOXML(), equiv);
                    } else {
                        equiv.dispose();
                        equiv = label_cache.get(s);
                    }
                    return equiv;
                } catch (SIOException e) {
                    // Ignore; missing encrypt.
                }
            }
        } catch (SIOException e) {
            Log.warn("Unexpected error during equiv mapping: ", e);
        }
        return null;
    }
    Label getEquiv(JID entity, Label input) {
        return getEquiv(entity, input, getSpiffingClearance(entity));
    }

    SecurityLabel rewrite(Label label) throws SIOException {
        SAXReader reader = new SAXReader();
        reader.setEncoding("UTF-8");
        try {
            Element nato = reader.read(new StringReader(label.toNATOXML())).getRootElement();

            return new SecurityLabel(label.displayMarking(), label.fgColour(), label.bgColour(), nato.createCopy());
        } catch(DocumentException e) {
            Log.warn("Encoded label does not parse: ", e);
            throw new SIOException("Label encoding error");
        }
    }

    public Label getDefaultLabel() {
        return defaultLabel;
    }

    public Collection<Label> getCatalogue() {
        return label_cache.values();
    }
}
