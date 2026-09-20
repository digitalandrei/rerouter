#!/usr/bin/env python3
"""Prepare reproducible hardening release evidence. Never deploys or mutates runtime state."""
import argparse,gzip,hashlib,io,json,os,pathlib,subprocess,sys,tarfile

CAPTURE_SQL = """-- READ ONLY: run with the approved restricted account against a dedicated capture target.
START TRANSACTION READ ONLY;
SELECT id,state,lifecycle_state,remaining_mutations,recovery_claim_token FROM reroute_bundles ORDER BY id;
SELECT id,user_id,scope,scope_id,consumed_at,bundle_id,snapshot_json,plan_hash,token_hash,expires_at,created_at FROM execution_plans ORDER BY id;
SET @capture_sql=IF(EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='action_previews'),'SELECT token_hash,user_id,scope,scope_id,plan_hash,expires_at,used_at,created_at FROM action_previews ORDER BY token_hash','SELECT NULL AS token_hash,NULL AS user_id,NULL AS scope,NULL AS scope_id,NULL AS plan_hash,NULL AS expires_at,NULL AS used_at,NULL AS created_at WHERE 1=0');
PREPARE capture_stmt FROM @capture_sql; EXECUTE capture_stmt; DEALLOCATE PREPARE capture_stmt;
SELECT id,device_id,bundle_id,rollback_of_reroute_id,mutation_effect,state,prior_state_json,after_state_json,planned_steps_json FROM reroutes ORDER BY id;
SELECT id,bundle_id,position,reroute_id,original_reroute_id,state,mutation_effect,rollback_snapshot_json,prepared_action_json FROM reroute_bundle_actions ORDER BY id;
SELECT id,scope,scope_ref,reroute_id,reason,cleared_at FROM locks ORDER BY id;
SELECT device_id,bundle_id,reroute_id,owner_token,phase FROM device_change_windows ORDER BY device_id;
SET @capture_sql=IF(EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='device_change_window_sources'),'SELECT device_id,source_bundle_id,created_at FROM device_change_window_sources ORDER BY device_id,source_bundle_id','SELECT NULL AS device_id,NULL AS source_bundle_id,NULL AS created_at WHERE 1=0');
PREPARE capture_stmt FROM @capture_sql; EXECUTE capture_stmt; DEALLOCATE PREPARE capture_stmt;
SET @capture_sql=IF(EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='recovery_attempt_sources'),'SELECT recovery_bundle_id,source_bundle_id,claim_token,settlement,created_at,settled_at FROM recovery_attempt_sources ORDER BY recovery_bundle_id,source_bundle_id','SELECT NULL AS recovery_bundle_id,NULL AS source_bundle_id,NULL AS claim_token,NULL AS settlement,NULL AS created_at,NULL AS settled_at WHERE 1=0');
PREPARE capture_stmt FROM @capture_sql; EXECUTE capture_stmt; DEALLOCATE PREPARE capture_stmt;
SELECT id,alert_id,delivery_intent_id,recipient_id,endpoint_id,channel,status,error,sent_at,created_at FROM alert_deliveries ORDER BY id;
SET @capture_sql=IF(EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='alert_delivery_intents'),'SELECT id,alert_id,channel,target_key,recipient_id,endpoint_id,target_address,target_encrypted,state,outcome,attempt_count,next_attempt_at,claimed_at,claim_token,last_error,settled_at,created_at,updated_at FROM alert_delivery_intents ORDER BY id','SELECT NULL AS id,NULL AS alert_id,NULL AS channel,NULL AS target_key,NULL AS recipient_id,NULL AS endpoint_id,NULL AS target_address,NULL AS target_encrypted,NULL AS state,NULL AS outcome,NULL AS attempt_count,NULL AS next_attempt_at,NULL AS claimed_at,NULL AS claim_token,NULL AS last_error,NULL AS settled_at,NULL AS created_at,NULL AS updated_at WHERE 1=0');
PREPARE capture_stmt FROM @capture_sql; EXECUTE capture_stmt; DEALLOCATE PREPARE capture_stmt;
COMMIT;
"""

SECTION_KEYS={
 "reroute_bundles":("id",),"execution_plans":("id",),"reroutes":("id",),
 "action_previews":("token_hash",),
 "reroute_bundle_actions":("id",),"locks":("id",),
 "device_change_windows":("device_id",),
 "device_change_window_sources":("device_id","source_bundle_id"),
 "recovery_attempt_sources":("recovery_bundle_id","source_bundle_id"),
 "alert_deliveries":("id",),
 "alert_delivery_intents":("id",),
}
REQUIRED_SECTIONS=set(SECTION_KEYS)

def sha256(data): return hashlib.sha256(data).hexdigest()
def file_digest(path):
    if not path or not path.exists(): return None
    if path.is_file(): return sha256(path.read_bytes())
    entries=[(str(p.relative_to(path)),sha256(p.read_bytes())) for p in sorted(path.rglob("*")) if p.is_file()]
    return sha256(json.dumps(entries,separators=(",",":")).encode())
def source_manifest(repo):
    tracked=subprocess.run(["git","ls-files","-co","--exclude-standard"],cwd=repo,text=True,capture_output=True,check=True).stdout.splitlines()
    entries=[]
    for rel in sorted(tracked):
        path=repo/rel
        if path.is_symlink(): raise ValueError(f"source package refuses symlink: {rel}")
        if path.is_file() and ".git" not in path.parts and "target" not in path.parts and "node_modules" not in path.parts:
            entries.append({"path":rel,"sha256":file_digest(path),"bytes":path.stat().st_size})
    dirty=subprocess.run(["git","diff","--binary","HEAD"],cwd=repo,capture_output=True,check=True).stdout
    untracked=[e for e in entries if subprocess.run(["git","ls-files","--error-unmatch",e["path"]],cwd=repo,capture_output=True).returncode != 0]
    digest=sha256(json.dumps(entries,sort_keys=True,separators=(",",":")).encode()+dirty)
    return entries,dirty,untracked,digest

def _archive_entry(archive,name,data,mode=0o644):
    info=tarfile.TarInfo(name); info.size=len(data); info.mode=mode
    info.mtime=0; info.uid=0; info.gid=0; info.uname=""; info.gname=""
    archive.addfile(info,io.BytesIO(data))

def build_archive(repo,output,entries,migrations,controller,frontend,safety_reference,head):
    target=output/"source-package.tar.gz"
    with target.open("wb") as raw, gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=0) as zipped, tarfile.open(fileobj=zipped,mode="w") as archive:
        for entry in entries:
            source=repo/entry["path"]
            mode=0o755 if os.access(source,os.X_OK) else 0o644
            _archive_entry(archive,f"source/{entry['path']}",source.read_bytes(),mode)
        _archive_entry(archive,"release/migrations.json",(json.dumps(migrations,sort_keys=True,indent=2)+"\n").encode())
        _archive_entry(archive,"release/source-head.txt",(head+"\n").encode())
        _archive_entry(archive,"release/candidate-safety-reference.json",(json.dumps(safety_reference,sort_keys=True,indent=2)+"\n").encode())
        if controller:
            if not controller.is_file() or controller.is_symlink(): raise ValueError("controller artifact must be a regular file")
            _archive_entry(archive,f"artifacts/controller/{controller.name}",controller.read_bytes(),0o755)
        if frontend:
            if not frontend.is_dir() or frontend.is_symlink(): raise ValueError("frontend artifact must be a regular directory")
            for source in sorted(frontend.rglob("*")):
                if source.is_symlink(): raise ValueError("frontend artifact may not contain symlinks")
                if source.is_file(): _archive_entry(archive,f"artifacts/frontend/{source.relative_to(frontend)}",source.read_bytes())
    return target

def _rows(snapshot,name):
    if name not in snapshot: raise ValueError(f"snapshot missing required section: {name}")
    value=snapshot[name]
    if not isinstance(value,list): raise ValueError(f"snapshot {name} must be a list")
    keys=SECTION_KEYS[name]; result={}
    for row in value:
        if not isinstance(row,dict) or any(key not in row for key in keys):
            raise ValueError(f"snapshot {name} row missing identity {keys}")
        identity=":".join(str(row[key]) for key in keys)
        if identity in result: raise ValueError(f"snapshot {name} has duplicate identity {identity}")
        result[identity]=row
    return result

def _assert_stopped(snapshot,label):
    missing=REQUIRED_SECTIONS-set(snapshot)
    if missing: raise ValueError(f"{label} snapshot missing required sections: {sorted(missing)}")
    active={"planned","pending","running","verifying","compensating"}
    rows=[r for r in snapshot["reroute_bundles"] if r.get("state") in active or r.get("lifecycle_state") in ("recovery_claimed","recovery_running")]
    rows += [r for r in snapshot["reroutes"] if r.get("state") in {"planned","pending","running","verifying"}]
    if rows: raise ValueError(f"{label} release window contains active execution or admitted recovery")

def compare_snapshots(before,after,predicted_repairs):
    _assert_stopped(before,"baseline"); _assert_stopped(after,"candidate")
    allowed={tuple(item.split(".",2)) for item in predicted_repairs}
    changes=[]
    protected_fields={"execution_plans":{"snapshot_json","plan_hash","consumed_at","bundle_id","user_id","scope","scope_id","created_at"},
      "action_previews":{"user_id","scope","scope_id","plan_hash","used_at","created_at"},
      "reroutes":{"prior_state_json","after_state_json","planned_steps_json","rollback_of_reroute_id"},
      "reroute_bundle_actions":{"rollback_snapshot_json","prepared_action_json","original_reroute_id","reroute_id"},
      "alert_delivery_intents":{"alert_id","channel","target_key","recipient_id","endpoint_id","target_address","target_encrypted","created_at"}}
    internal={"device_change_windows","device_change_window_sources","recovery_attempt_sources","alert_delivery_intents"}
    for section in sorted(REQUIRED_SECTIONS-{"alert_deliveries"}):
        old,new=_rows(before,section),_rows(after,section)
        removed=old.keys()-new.keys(); added=new.keys()-old.keys()
        for rid in removed|added:
            marker=(section,rid,"__row__")
            if section not in internal or marker not in allowed:
                raise ValueError(f"{section} identities changed without predicted internal repair: {rid}")
            changes.append(".".join(marker))
        for rid in old:
            if rid not in new: continue
            keys=set(old[rid])|set(new[rid])
            for key in keys:
                if old[rid].get(key)!=new[rid].get(key):
                    marker=(section,rid,key)
                    if key in protected_fields.get(section,set()):
                        raise ValueError(f"protected evidence changed: {section}.{rid}.{key}")
                    if marker not in allowed: raise ValueError(f"history changed without predicted repair: {section}.{rid}.{key}")
                    changes.append(".".join(marker))
    old,new=_rows(before,"alert_deliveries"),_rows(after,"alert_deliveries")
    if old.keys()!=new.keys(): raise ValueError("alert delivery history identities changed")
    for rid in old:
        for key in set(old[rid])|set(new[rid]):
            if old[rid].get(key)!=new[rid].get(key):
                marker=("alert_deliveries",rid,key)
                if marker not in allowed or key not in ("delivery_intent_id","error"):
                    raise ValueError(f"alert history changed outside link/scrub: {'.'.join(marker)}")
                changes.append(".".join(marker))
    return {"active_execution":False,"ordinary_lock_count":len([r for r in after["locks"] if not r.get("cleared_at")]),"accepted_predicted_repairs":sorted(changes)}

def prepare(repo,output,controller=None,frontend=None,before=None,after=None,predicted=()):
    repo=repo.resolve(); output=output.resolve()
    if output==repo or output.is_relative_to(repo): raise ValueError("release output must be outside the source repository")
    if controller: controller=(controller if controller.is_absolute() else repo/controller).resolve()
    if frontend: frontend=(frontend if frontend.is_absolute() else repo/frontend).resolve()
    entries,dirty,untracked,source_digest=source_manifest(repo)
    migrations=[]
    for path in sorted((repo/"backend-rust/migrations").glob("*.sql")):
        migrations.append({"name":path.name,"sha256":file_digest(path)})
    comparison=None
    if before or after:
        if not before or not after: raise ValueError("both baseline and candidate snapshots are required")
        comparison=compare_snapshots(json.loads(before.read_text()),json.loads(after.read_text()),predicted)
    output.mkdir(parents=True,exist_ok=True)
    (output/"dirty.patch").write_bytes(dirty)
    (output/"capture-read-only.sql").write_text(CAPTURE_SQL)
    head=subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,capture_output=True,check=True).stdout.strip()
    safety_reference={"operating_mode":"observe","automatic_actions_enabled":False,"purpose":"candidate reference only; no live setting was read or changed"}
    (output/"candidate-safety-reference.json").write_text(json.dumps(safety_reference,indent=2,sort_keys=True)+"\n")
    archive=build_archive(repo,output,entries,migrations,controller,frontend,safety_reference,head)
    manifest={"schema":2,"source_head":head,"source_digest":source_digest,"source_files":entries,"dirty_patch_sha256":sha256(dirty),"source_archive":{"path":archive.name,"sha256":file_digest(archive)},
      "untracked_source_files":[e["path"] for e in untracked],"migration_count":len(migrations),"migrations":migrations,
      "controller":{"path":str(controller) if controller else None,"sha256":file_digest(controller)},
      "frontend":{"path":str(frontend) if frontend else None,"sha256":file_digest(frontend)},"baseline_comparison":comparison,
      "certification":{"source_and_model":"separate owner-controlled evidence; not inferred by this tool"},
      "candidate_safety_reference":safety_reference,"actions_performed":[]}
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    return manifest

def main():
    p=argparse.ArgumentParser(); p.add_argument("--repo",type=pathlib.Path,default=pathlib.Path.cwd()); p.add_argument("--output",type=pathlib.Path,required=True)
    p.add_argument("--controller",type=pathlib.Path); p.add_argument("--frontend",type=pathlib.Path); p.add_argument("--baseline",type=pathlib.Path); p.add_argument("--candidate",type=pathlib.Path); p.add_argument("--predicted-repair",action="append",default=[])
    a=p.parse_args(); print(json.dumps(prepare(a.repo.resolve(),a.output,a.controller,a.frontend,a.baseline,a.candidate,a.predicted_repair),sort_keys=True))
if __name__=="__main__":
    try: main()
    except (ValueError,KeyError,json.JSONDecodeError,subprocess.SubprocessError) as error: print(f"refused: {error}",file=sys.stderr); sys.exit(2)
