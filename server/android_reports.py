"""Allowlisted Android diagnostics. No raw log strings, credentials or addresses."""
import re
from support_reports import clean_bundle, number, PATHS
PHASES={'flow','flow_health','start','connected','health_ok','health_failed','failed','failover','network_changed','candidate_failed','rank','measurement','packet','packet_server','dns','baseline','load','transfer'}
ERRORS={*("ike_"+s for s in ('auth_failed','peer_auth_failed','lookup_failed','unreachable','generic_error','password_missing','certificate_unavailable','timeout')),'none','timeout','dns','certificate','authentication','network','cancel','unexpected_exit','carrier','http','other'}
COUNTERS=set('sent_bytes received_bytes enqueued sent_packets received_packets queue_drops stale_drops sequence_gaps queue_depth heartbeat_rtt_ms heartbeat_timeouts max_queue_ms max_write_ms write_timeouts write_ms flushes reconnects udp_receive_buffer batch_packets max_age_ms dial_attempts connect_ms tcp_send_buffer tcp_receive_buffer started_at'.split())
VALUES=set('down up latency connect_ms elapsed_ms score losses bytes_per_direction size burst sent received duplicates reordered invalid loss_percent rtt_p50_ms rtt_p95_ms rtt_max_ms jitter_ms control_ms server_received server_replies server_duplicates dns_queries dns_success dns_timeouts dns_total_ms tcp_attempts tcp_success tcp_failed tcp_pending tcp_cancelled tcp_p50_ms tcp_p95_ms tcp_max_ms down_max_read_ms up_max_write_ms discord_ms down_setup_ms down_body_ms up_setup_ms up_write_ms up_body_ack_ms stage flow_size flow_client_written flow_write_ms flow_ack_ms flow_server_received flow_server_complete flow_server_ms flow_server_max_read_ms flow_result_available flow_endpoint flow_stage flow_elapsed_ms flow_response_wait_ms'.split())
def metrics(value,keys):
 if not isinstance(value,dict):raise ValueError('metrics')
 return {k:number(v) for k,v in value.items() if k in keys}
def values(value):
 result=metrics(value,VALUES)
 if 'flow_id' in value:
  if not isinstance(value['flow_id'],str) or not re.fullmatch('[a-f0-9]{32}',value['flow_id']):raise ValueError('flow_id')
  result['flow_id']=value['flow_id']
 if 'discord_ok' in value:result['discord_ok']=value['discord_ok'] is True
 if 'metrics' in value:
  result['metrics']=metrics(value['metrics'],VALUES)
  if 'discord_ok' in value['metrics']:result['metrics']['discord_ok']=value['metrics']['discord_ok'] is True
 return result
def clean_android(body):
 if body.get('system')!='android':raise ValueError('system')
 result=clean_bundle({**body,'system':'other'});result['system']='android'
 a=body.get('android')
 if not isinstance(a,dict):raise ValueError('android')
 sdk=a.get('sdk')
 if type(sdk)!=int or not 26<=sdk<=100:raise ValueError('sdk')
 metadata={'sdk':sdk}
 for key in ('always_on','lockdown'):
  if key in a:metadata[key]=a[key] is True
 for k in ('manufacturer','model'):
  v=a.get(k)
  if not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9 ._()+-]{1,64}',v) or 'EVN1-' in v:raise ValueError('hardware')
  metadata[k]=v
 if a.get('outcome') not in ('snapshot','completed','incomplete','cancelled'):raise ValueError('outcome')
 metadata['outcome']=a['outcome']
 rows=a.get('samples',[])
 if not isinstance(rows,list) or len(rows)>128:raise ValueError('samples')
 metadata['samples']=[]
 for r in rows:
  if not isinstance(r,dict) or r.get('phase') not in PHASES or r.get('path') not in PATHS or r.get('network') not in ('wifi','cellular','unknown') or r.get('error') not in ERRORS:raise ValueError('sample')
  metadata['samples'].append({**{k:r[k] for k in ('phase','path','network','error')},'time':number(r.get('time',0)), 'screen_on':r.get('screen_on') is True,'device_idle':r.get('device_idle') is True,'carrier':metrics(r.get('carrier',{}),COUNTERS),'values':values(r.get('values',{}))})
 rankings=a.get('rankings',{})
 if not isinstance(rankings,dict) or len(rankings)>2:raise ValueError('rankings')
 metadata['rankings']={}
 for network,rank in rankings.items():
  if network not in ('wifi','cellular') or not isinstance(rank,dict):raise ValueError('ranking')
  rows=rank.get('paths',[])
  if not isinstance(rows,list) or len(rows)>5:raise ValueError('paths')
  safe=[]
  for r in rows:
   if not isinstance(r,dict) or r.get('id') not in PATHS-{''} or r.get('error') not in ERRORS:raise ValueError('path')
   safe.append({**values(r),'id':r['id'],'error':r['error']})
  metadata['rankings'][network]={'created':number(rank.get('created',0)),'paths':safe}
 result['android']=metadata
 return result
