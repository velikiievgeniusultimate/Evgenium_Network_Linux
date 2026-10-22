/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.net.*;
import android.os.ParcelFileDescriptor;
/**
 * Never select IMS/emergency/carrier provisioning networks as Internet
 * transport.
 */
public final class NetworkAccess {
  public static Network select(Context context) {
    ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
    Network active = cm.getActiveNetwork(), candidate = null;
    int best = -1;
    for (Network n : cm.getAllNetworks()) {
      NetworkCapabilities c = cm.getNetworkCapabilities(n);
      if (c == null || c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
          || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED))
        continue;
      int score = (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ? 4 : 0)
          + (n.equals(active) ? 2 : 0)
          + (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ? 1 : 0);
      if (score > best) {
        candidate = n;
        best = score;
      }
    }
    return candidate;
  }
  public static String kind(Context context, Network network) {
    ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
    NetworkCapabilities c = network == null ? null : cm.getNetworkCapabilities(network);
    if (c == null)
      return "unknown";
    if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
      return "wifi";
    if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
      return "cellular";
    return "other";
  }
  public static boolean bind(VpnService service, int fd) {
    Network network = select(service);
    if (network == null)
      return false;
    try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd(fd)) {
      network.bindSocket(duplicate.getFileDescriptor());
      service.setUnderlyingNetworks(new Network[] {network});
      return true;
    } catch (Exception e) {
      android.util.Log.w("Evgenium", "bind_transport_" + e.getClass().getSimpleName());
      return false;
    }
  }
}
