/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import java.io.IOException;
/** A single diagnostic service outage must not evict a working VPN route. */
final class TransferHealth {
  static final class ServiceUnavailable extends IOException { ServiceUnavailable() { super("http_service_unavailable"); } }
  interface Probe<T> { T run(int endpoint) throws Exception; }
  <T> T check(Probe<T> probe) throws Exception {
    Exception last=null; boolean unavailable=false;
    for(int endpoint=0;endpoint<2;endpoint++) {
      try{return probe.run(endpoint);}
      catch(InterruptedException e){Thread.currentThread().interrupt();throw e;}
      catch(ServiceUnavailable e){unavailable=true;last=e;}
      catch(Exception e){last=e;}
    }
    if(unavailable)return null; // No independent confirmation: retain ordinary exit monitoring.
    throw new IOException("partial_transfer_timeout",last);
  }
}
