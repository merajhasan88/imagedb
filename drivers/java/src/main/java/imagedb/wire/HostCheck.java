package imagedb.wire;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * A CA-verified server's name against its certificate's subjectAltName (as tls.c's X509_VERIFY_PARAM_set1_host and
 * set1_ip_asc): an address literal against the iPAddress entries, a host name against the dNSName entries (exact,
 * ignoring case, or a wildcard as the left-most label alone); no fallback to the subject's CN. Applied on every TLS
 * stack, so the driver's rule does not depend on which one connected.
 */
public final class HostCheck {
    private HostCheck() {}

    /** an IPv4 dotted quad or an IPv6 literal, parsed without any lookup; null for a host name */
    static InetAddress literal(String name) {
        boolean v4 = name.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}"), v6 = name.indexOf(':') >= 0 && name.matches("[0-9A-Fa-f:.]+");
        if (!v4 && !v6) return null;
        if (v4)
            for (String p : name.split("\\."))
                if (Integer.parseInt(p) > 255) return null;
        try {
            return InetAddress.getByName(name); // a literal: no lookup is made
        } catch (UnknownHostException x) {
            return null;
        }
    }

    public static boolean matches(X509Certificate c, String name) {
        if (name == null || name.isEmpty()) return false;
        Collection<List<?>> sans;
        try {
            sans = c.getSubjectAlternativeNames();
        } catch (CertificateParsingException x) {
            return false;
        }
        if (sans == null) return false;
        InetAddress ip = literal(name);
        for (List<?> e : sans) {
            int type = (Integer) e.get(0);
            String v = String.valueOf(e.get(1));
            if (ip != null && type == 7) {
                InetAddress a = literal(v);
                if (a != null && a.equals(ip)) return true;
            } else if (ip == null && type == 2 && dnsMatch(v, name)) {
                return true;
            }
        }
        return false;
    }

    static boolean dnsMatch(String pattern, String name) {
        String p = pattern.toLowerCase(Locale.ROOT), n = name.toLowerCase(Locale.ROOT);
        if (p.endsWith(".")) p = p.substring(0, p.length() - 1);
        if (n.endsWith(".")) n = n.substring(0, n.length() - 1);
        if (!p.startsWith("*.")) return p.equals(n);
        String rest = p.substring(1); // ".example.com"
        if (rest.indexOf('*') >= 0 || rest.split("\\.").length < 3) return false; // a wildcard over two labels at least
        int dot = n.indexOf('.');
        return dot > 0 && n.substring(dot).equals(rest);
    }
}
