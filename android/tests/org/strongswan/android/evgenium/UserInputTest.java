package org.strongswan.android.evgenium;
import static org.junit.Assert.*;
import org.junit.Test;
public class UserInputTest {
  @Test public void connectionErrorsHaveActionableMessagesWithoutEchoingPayloads() {
    assertTrue(UserMessages.connection("ike_AUTH_FAILED").contains("доступ"));
    assertTrue(UserMessages.connection("SocketTimeoutException").contains("не ответил"));
    // Transient errors are retried by Engine; they must not direct a normal
    // user to the old manual-repair workflow.
    for (String error : new String[]{"SocketTimeoutException", "health_failed", "unknown"}) {
      String message = UserMessages.connection(error).toLowerCase(java.util.Locale.ROOT);
      assertFalse(message.contains("в настройках"));
      assertFalse(message.contains("восстановление"));
      assertFalse(message.contains("запустите"));
    }
    assertTrue(UserMessages.connection("CertificateExpiredException").contains("дату"));
    assertTrue(UserMessages.connection("UnknownHostException").contains("имени"));
    assertFalse(UserMessages.connection("EVN1-secret").contains("EVN1"));
    assertFalse(UserMessages.connection(null).isEmpty());
  }
  @Test public void pastedTokenAllowsOuterWhitespaceOnly() {
    String t="EVN1-"+new String(new char[43]).replace('\0','a');
    assertEquals(t, UserInput.token("\n "+t+" \n"));
    for(String bad:new String[]{"", " ",t+"x",t.substring(1),t.substring(0,15)+" "+t.substring(15),"https://example.org/"+t}) {
      try { UserInput.token(bad); fail(); } catch(IllegalArgumentException expected) {}
    }
  }
  @Test public void namesAreValidatedByUnicodeCharacters() {
    assertEquals("Телефон 📱", UserInput.name(" Телефон 📱 "));
    String emoji=new String(Character.toChars(0x1f4f1));
    StringBuilder b=new StringBuilder();for(int i=0;i<64;i++)b.append(emoji);
    assertEquals(b.toString(),UserInput.name(b.toString()));
    for(String bad:new String[]{" ","abc\ndef","x\u0000y",b.toString()+emoji}) {
      try { UserInput.name(bad); fail(); } catch(IllegalArgumentException expected) {}
    }
  }
}
