package com.surevine.spiffing.openfire;

import com.surevine.spiffing.Clearance;
import com.surevine.spiffing.Label;
import com.surevine.spiffing.SIOException;
import com.surevine.spiffing.Site;
import org.dom4j.Element;
import org.jivesoftware.openfire.IQHandlerInfo;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.handler.IQHandler;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;

public class CatalogueHandler extends IQHandler {
    private final IQHandlerInfo info;
    private final PluginMain plugin;
    private boolean ns2;
    public final static String NS0_CATALOG = "urn:xmpp:sec-label:catalog:0";
    public final static String NS2_CATALOG = "urn:xmpp:sec-label:catalog:2";

    public CatalogueHandler(PluginMain plugin, boolean ns2) {
        super("XEP-0258 Catalogue Handler");
        this.plugin = plugin;
        this.info = new IQHandlerInfo("catalog", ns2 ? NS2_CATALOG : NS0_CATALOG);
        this.ns2 = ns2;
    }

    void addCatItem(Element catalog, Label label) throws SIOException {
        if (ns2) {
            Element item = catalog.addElement("item");
            item.addAttribute("selector", label.displayMarking());

            this.plugin.populate258(item.addElement("securitylabel", "urn:xmpp:sec-label:0"), label);
        } else {
            this.plugin.populate258(catalog.addElement("securitylabel", "urn:xmpp:sec-label:0"), label);
        }
    }

    @Override
    public IQ handleIQ(IQ packet) throws UnauthorizedException {
        IQ reply = IQ.createResultIQ(packet);
        Set<String> included = new HashSet<>();
        Element catalog = reply.setChildElement("catalog", ns2 ? NS2_CATALOG : NS0_CATALOG);
        Element req = packet.getChildElement();
        LinkedHashMap<String,Clearance> source_clearance = this.plugin.getClearance(packet.getFrom());
        LinkedHashMap<String,Clearance> target_clearance = this.plugin.getClearance(new JID(req.attributeValue("to")));
        // Add some attributes.
        for (Label label : this.plugin.catalogue()) {
            try {
                String dm = label.displayMarking();
                if (included.contains(dm)) {
                    continue;
                }
                boolean needs_adding = true;
                // There is a source and target jid. We want to present the source user with a list of labels
                // which they understand, but ideally that the target also understands.
                // So if the catalog entry is UK, and the user has UK/NATO, and the target is NATO only, the
                // label should be presented to the source user as NATO.
                // Therefore, iterate through all source user clearances to find the first match with the target,
                // and translate. If this fails, just find any source clearance.
                String cat_policy = label.policy().policy_id();
                // First look for simple match:
                if (source_clearance.containsKey(cat_policy) && target_clearance.containsKey(cat_policy)) {
                    addCatItem(catalog, label);
                    needs_adding = false;
                } else {
                    // Now iterate through available source policies and see if we can find a policy match.
                    for (String source_policy : source_clearance.keySet()) {
                        if (target_clearance.containsKey(source_policy)) {
                            try (Label equiv = label.encrypt(Site.site().spif(source_policy))) {
                                if (source_clearance.get(source_policy).dominates(equiv)) {
                                    if (target_clearance.get(source_policy).dominates(equiv)) {
                                        addCatItem(catalog, equiv);
                                        needs_adding = false;
                                        break;
                                    }
                                } else {
                                    // Failed ACDF, give up on this label.
                                    needs_adding = false;
                                    break;
                                }
                            } catch (Exception e) {
                                continue;
                            }
                        }
                    }
                }
                if (needs_adding) {
                    // Still not added; try performing basic clearance checks instead.
                    try (Label equiv = this.plugin.doACDF(source_clearance, label)) {
                        try (Label equiv2 = this.plugin.doACDF(target_clearance, equiv == null ? label : equiv)) {
                            addCatItem(catalog, equiv == null ? label : equiv);
                        }
                    } catch (Exception e) {
                        continue;
                    }
                }
            } catch (SIOException e) {
                // Nothing
            }
        }
        return reply;
    }

    @Override
    public IQHandlerInfo getInfo() {
        return info;
    }
}
