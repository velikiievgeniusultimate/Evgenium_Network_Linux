#!/usr/bin/env python3
"""Apply the small Evgenium overlay to a pinned, unmodified strongSwan checkout."""
import argparse,pathlib,shutil,subprocess,os,re
p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('--sdk',required=True,type=pathlib.Path);a=p.parse_args()
release=os.environ.get('EVG_ANDROID_RELEASE')=='1'
package='com.evgenium.network' if release else 'com.evgenium.network.lab'
root=pathlib.Path(__file__).resolve().parent;src=a.source.resolve();app=src/'src/frontends/android/app';main=app/'src/main'
assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='5e410617d4c9d06cff5b860a26f51ee91aa73228'
def original(path):return subprocess.check_output(['git','-C',str(src),'show','HEAD:'+str(path.relative_to(src))],text=True)
for path in (root/'overlay').rglob('*'):
 if path.is_file():target=main/path.relative_to(root/'overlay');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
for path in (root/'tests').rglob('*.java'):
 target=app/'src/test/java'/path.relative_to(root/'tests');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
f=app/'build.gradle';s=original(f).replace('applicationId "org.strongswan.android"','applicationId "'+package+'"').replace('minSdkVersion 21','minSdkVersion 26').replace('versionCode 96','versionCode 12').replace('versionName "2.6.2"','versionName "0.2.1-beta"');abis=os.environ.get('EVG_ANDROID_ABIS','arm64-v8a armeabi-v7a x86_64').split();assert set(abis)<= {'arm64-v8a','armeabi-v7a','x86_64'};s=s.replace("arguments '-j' + Runtime.runtime.availableProcessors()","arguments '-j4'\n                abiFilters "+', '.join(repr(x) for x in abis));s=s.replace("dependencies {", "dependencies {\n    implementation 'org.conscrypt:conscrypt-android:2.7.0'")
s=s.replace('defaultConfig {', 'defaultConfig {\n        ndk { abiFilters '+', '.join(repr(x) for x in abis)+' }', 1)
f.write_text(s)
f=main/'jni/Android.mk';f.write_text(original(f).replace('-DHAVE_STDBOOL_H', '-DHAVE_STDBOOL_H -DHAVE_SIGWAITINFO'))
f=main/'AndroidManifest.xml';s=original(f).replace('android:name=".ui.MainActivity"','android:name=".evgenium.HomeActivity"',1).replace('android:label="@string/main_activity_name"','android:label="Evgenium Network"',1)
s=s.replace('android:icon="@mipmap/ic_launcher"', 'android:icon="@drawable/evgenium_icon"', 1)
s=s.replace('android:label="@string/app_name"','android:label="'+('Evgenium Network' if release else 'Evgenium Network · Lab')+'"',1)
s=s.replace('    </application>','        <activity android:name=".ui.MainActivity" android:exported="false" />\n        <service android:name=".evgenium.Engine" android:exported="false" android:foregroundServiceType="specialUse"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="VPN connection orchestration and consented route testing" /></service>\n    </application>')
s=s.replace('    </application>', '    </application>\n    <uses-permission android:name="android.permission.WAKE_LOCK" />')
s=s.replace('    </application>', '        <provider android:name="androidx.core.content.FileProvider" android:authorities="'+package+'.updates" android:exported="false" android:grantUriPermissions="true"><meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/update_paths" /></provider>\n    </application>')
s=s.replace('</manifest>', '<queries><package android:name="com.evgenium.network" /></queries>\n</manifest>')
s=s.replace('</manifest>', '    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />\n    </manifest>')
for permission in ('READ_EXTERNAL_STORAGE','SYSTEM_ALERT_WINDOW','QUERY_ALL_PACKAGES'):
 s=re.sub(r'<uses-permission android:name="android.permission.'+permission+r'"[^>]*/>', '', s)
# Keep upstream native namespace; use a distinct application ID and component names.
s=s.replace('android:name=".','android:name="org.strongswan.android.')
s=s.replace('android:authorities="org.strongswan.android', 'android:authorities="'+package)
# Evgenium has one token-based control surface. Do not expose upstream import/control UIs.
for component in ('ui.VpnProfileControlActivity', 'ui.VpnProfileSelectActivity',
                  'ui.VpnProfileImportActivity', 'ui.TrustedCertificateImportActivity'):
 s=re.sub(r'(<activity\s+android:name="org\.strongswan\.android\.'+re.escape(component)+r'"[^>]*?)android:exported="true"', r'\1android:exported="false"', s)
s=s.replace('android:label="@string/tile_default"', 'android:label="Evgenium VPN"')
s=re.sub(r'(<provider\s+android:name="org\.strongswan\.android\.data\.LogContentProvider"[^>]*?)android:exported="true"',r'\1android:exported="false"',s)
f.write_text(s)
f=main/'java/org/strongswan/android/logic/CharonVpnService.java';s=original(f)
s=s.replace('public class CharonVpnService extends VpnService', 'public class CharonVpnService extends VpnService')
pos=s.index('\n',s.index('private static final String TAG'))
s=s[:pos]+ '\n\tprivate org.strongswan.android.evgenium.TunnelCarrier evgeniumCarrier;'+s[pos:]
s=s.replace('public void onCreate()','public boolean protect(int fd) { return super.protect(fd) && org.strongswan.android.evgenium.NetworkAccess.bind(this,fd); }\n\t@Override\n\tpublic void onCreate()',1)
s=s.replace('SettingsWriter writer = new SettingsWriter();','''if ("127.0.0.1".equals(mCurrentProfile.getGateway())) {
                                try { evgeniumCarrier = new org.strongswan.android.evgenium.TunnelCarrier(this,
                                    getSharedPreferences("evgenium",0).getString("route","").startsWith("ee-evgt")); }
                                catch (Exception e) { Log.e("Evgenium","carrier_start_"+e.getClass().getSimpleName());setError(ErrorState.GENERIC_ERROR);continue; }
                            }
                            SettingsWriter writer = new SettingsWriter();''')
s=s.replace('deinitializeCharon();','deinitializeCharon();\n                if (evgeniumCarrier != null) { evgeniumCarrier.close(); evgeniumCarrier = null; }',1)
s=s.replace('ArrayList<byte[]> certs = new ArrayList<byte[]>();','''if (org.strongswan.android.evgenium.Credentials.ALIAS.equals(mCurrentCertificateAlias)) {
            try { return new byte[][]{org.strongswan.android.evgenium.Credentials.ca(this).getEncoded()}; }
            catch(Exception e) { return null; }
        }
        ArrayList<byte[]> certs = new ArrayList<byte[]>();''',1)
s=s.replace('ArrayList<byte[]> encodings = new ArrayList<byte[]>();','''if (org.strongswan.android.evgenium.Credentials.ALIAS.equals(mCurrentUserCertificateAlias)) {
            try { return new byte[][]{org.strongswan.android.evgenium.Credentials.certificate(this).getEncoded(),org.strongswan.android.evgenium.Credentials.ca(this).getEncoded()}; }
            catch(Exception e) { return null; }
        }
        ArrayList<byte[]> encodings = new ArrayList<byte[]>();''',1)
s=s.replace('return KeyChain.getPrivateKey(getApplicationContext(), mCurrentUserCertificateAlias);','''if (org.strongswan.android.evgenium.Credentials.ALIAS.equals(mCurrentUserCertificateAlias)) {
            try { return org.strongswan.android.evgenium.Credentials.key(); } catch(Exception e) { return null; }
        }
        return KeyChain.getPrivateKey(getApplicationContext(), mCurrentUserCertificateAlias);''')
s=s.replace('mSelectedApps.add(getPackageName());', 'if (!org.strongswan.android.evgenium.Credentials.ALIAS.equals(profile.getUserCertificateAlias())) mSelectedApps.add(getPackageName());')
# System always-on starts the same orchestrator as the UI.
s=s.replace('private org.strongswan.android.evgenium.TunnelCarrier evgeniumCarrier;', 'private org.strongswan.android.evgenium.TunnelCarrier evgeniumCarrier;\n    public static volatile CharonVpnService evgeniumInstance;')
s=s.replace('mLogFile = getFilesDir()', 'evgeniumInstance = this;\n        mLogFile = getFilesDir()',1)
s=s.replace('mTerminate = true;', 'if (evgeniumInstance == this) evgeniumInstance = null;\n        mTerminate = true;',1)
s=s.replace('VpnProfile profile = null;', '''if (VPN_SERVICE_ACTION.equals(intent.getAction())) {
                startForeground(VPN_STATE_NOTIFICATION_ID,
                    new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
                        .setSmallIcon(R.drawable.ic_notification)
                        .setContentTitle("Evgenium Network")
                        .setContentText("Восстанавливаю защищённое подключение")
                        .setOngoing(true).build());
                Intent engine = new Intent(this, org.strongswan.android.evgenium.Engine.class)
                    .putExtra("command", "connect").putExtra("route",
                        getSharedPreferences("evgenium",0).getInt("wanted-route",-1));
                startForegroundService(engine);
                return START_STICKY;
            }
            VpnProfile profile = null;''',1)
s=s.replace('setNextProfile(null);\n\t}\n\n\t@Override\n\tpublic void onDestroy()', '''getSharedPreferences("evgenium",0).edit().putBoolean("connection-wanted",false).commit();
        stopService(new Intent(this, org.strongswan.android.evgenium.Engine.class));
        setNextProfile(null);
    }

    @Override
    public void onDestroy()''',1)
s=s.replace('new Intent(getApplicationContext(), MainActivity.class)', 'new Intent(getApplicationContext(), org.strongswan.android.evgenium.HomeActivity.class)')
s=s.replace('new Intent(getApplicationContext(), VpnProfileControlActivity.class)', 'new Intent(getApplicationContext(), org.strongswan.android.evgenium.HomeActivity.class)')
f.write_text(s)
# Engine owns route retries and the three-loss budget for Evgenium profiles.
f=main/'java/org/strongswan/android/logic/VpnStateService.java';s2=original(f)
s2=s2.replace('mRetryTimeout = mRetryIn = mTimeoutProvider.getTimeout(error);', 'if (mProfile != null && org.strongswan.android.evgenium.Credentials.ALIAS.equals(mProfile.getUserCertificateAlias())) { resetRetryTimer(); return; }\n        mRetryTimeout = mRetryIn = mTimeoutProvider.getTimeout(error);')
f.write_text(s2)
f=main/'java/org/strongswan/android/logic/NetworkManager.java';s2=original(f).replace('new NetworkRequest.Builder();','new NetworkRequest.Builder().addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET);');f.write_text(s2)
# Modern Android may deny exact alarms. Never lose IKE retransmit/rekey jobs.
f=main/'java/org/strongswan/android/logic/Scheduler.java';s2=original(f)
s2=s2.replace('private final PriorityQueue<ScheduledJob> mJobs;', 'private final PriorityQueue<ScheduledJob> mJobs;\n    private final android.os.Handler fallback = new android.os.Handler(android.os.Looper.getMainLooper());\n    private final Runnable wake = () -> onReceive(mContext, null);')
s2=s2.replace('private final Runnable wake = () -> onReceive(mContext, null);','private final Runnable wake = () -> onReceive(null, null);')
s2=s2.replace('mManager.cancel(createIntent());','mManager.cancel(createIntent());\n        fallback.removeCallbacksAndMessages(null);')
s2=s2.replace('System.currentTimeMillis()', 'android.os.SystemClock.elapsedRealtime()')
s2=s2.replace('mManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, job.Time, pending);', 'scheduleAlarm(job.Time, pending);')
s2=s2.replace('public native void executeJob(String id);', """private void scheduleAlarm(long at, PendingIntent pending) {
        fallback.removeCallbacks(wake);
        if (Build.VERSION.SDK_INT >= 31 && !mManager.canScheduleExactAlarms()) {
            mManager.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending);
            fallback.postDelayed(wake, Math.max(0, at - android.os.SystemClock.elapsedRealtime()));
        } else { mManager.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending); }
    }
    public native void executeJob(String id);""")
f.write_text(s2)
(src/'src/frontends/android/local.properties').write_text('sdk.dir='+str(a.sdk.resolve())+'\n')
# Release tarball supplies generated parser/version files absent from Git.
generated=src.parent/'strongswan-6.0.3'
for name in ('Android.common.mk','src/libstrongswan/crypto/proposal/proposal_keywords_static.c','src/libstrongswan/crypto/proposal/proposal_keywords_static.h','src/libstrongswan/asn1/oid.c','src/libstrongswan/asn1/oid.h','src/libstrongswan/settings/settings_parser.c','src/libstrongswan/settings/settings_parser.h','src/libstrongswan/settings/settings_lexer.c','src/libstrongswan/settings/settings_lexer.h'):
 source=generated/name
 if source.exists():shutil.copyfile(source,src/name)
print('Prepared Evgenium Android 0.2.0 beta')
