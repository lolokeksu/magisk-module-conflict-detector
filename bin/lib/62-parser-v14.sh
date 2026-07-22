scan_script() {
    module_root="$1"; module="$2"; script_name="$3"; file="$module_root/$script_name"
    [ -f "$file" ] || return
    awk -v module="$module" -v script="$script_name" '
        BEGIN { OFS="\t"; pending="" }
        function trim(s){gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s}
        function clean(s){gsub(/^["\047]+|["\047,;]+$/, "", s); return s}
        function command_name(s){sub(/^.*\//, "", s); return s}
        function isliteral(s){return s!="" && s !~ /[`*?\[\]{}()]/}
        function expand(s, k){
            s=clean(s)
            for(k in vars){gsub("\\$\\{" k "\\}", vars[k], s); gsub("\\$" k, vars[k], s)}
            return s
        }
        function emit(resource,value,op){
            resource=expand(resource); value=expand(trim(value))
            if(!isliteral(resource)) return
            if(value ~ /[$`]/) value="__DYNAMIC__"
            print resource,module,value,script ":" NR,op
        }
        function parse(work, n,a,i,j,cmd,key,value,ns,target,token,before,eq,mode,pkg){
            n=split(work,a,/[[:space:]]+/)
            for(i=1;i<=n;i++){
                cmd=command_name(clean(a[i]))
                if(cmd=="setprop" || cmd=="resetprop"){
                    j=i+1; deleted=0
                    while(j<=n && a[j] ~ /^-/){if(a[j]=="--delete"||a[j]=="-d")deleted=1;j++}
                    key=expand(a[j]); value=expand(a[j+1]); if(deleted)value="__DELETE__"
                    emit("prop:" key,value,cmd)
                }
                if(cmd=="settings" && (a[i+1]=="put" || a[i+1]=="delete")){
                    ns=clean(a[i+2]); key=clean(a[i+3]); value=(a[i+1]=="delete"?"__DELETE__":clean(a[i+4]))
                    emit("setting:" ns ":" key,value,"settings_" a[i+1])
                }
                if(cmd=="device_config" && (a[i+1]=="put" || a[i+1]=="delete")){
                    ns=clean(a[i+2]); key=clean(a[i+3]); value=(a[i+1]=="delete"?"__DELETE__":clean(a[i+4]))
                    emit("device_config:" ns ":" key,value,"device_config_" a[i+1])
                }
                if(cmd=="sysctl") for(j=i+1;j<=n;j++){token=clean(a[j]);if(token~/^[A-Za-z0-9_.-]+=/){eq=index(token,"=");emit("sysctl:" substr(token,1,eq-1),substr(token,eq+1),"sysctl")}}
                if(cmd=="write" && a[i+1]~/^\//) emit("sysfs:" clean(a[i+1]),clean(a[i+2]),"write")
                if(cmd=="tee"){
                    target=""; for(j=i+1;j<=n;j++){token=clean(a[j]);if(token~/^\/(sys|proc\/sys)\//)target=token}
                    if(target!=""){before=work;sub(/[[:space:]]*\|[[:space:]]*.*$/, "", before);sub(/^[[:space:]]*(echo|printf)[[:space:]]+/, "", before);emit("sysfs:" target,before,"tee")}
                }
                if(cmd=="mount" || cmd=="umount"){
                    target="";for(j=i+1;j<=n;j++){token=clean(a[j]);if(token~/^\//)target=token}
                    if(target!="")emit("mount:" target,(cmd=="umount"?"unmount":work),cmd)
                }
                if(cmd=="magiskpolicy" || cmd=="supolicy") if(work~/--live/)emit("sepolicy:live",work,cmd)
                if(cmd=="setenforce") emit("sepolicy:enforcing",clean(a[i+1]),"setenforce")
                if(cmd=="cmd" && a[i+1]=="overlay" && (a[i+2]=="enable"||a[i+2]=="disable")) emit("overlay:" clean(a[i+3]),a[i+2],"cmd_overlay")
                if(cmd=="pm" && (a[i+1]=="enable"||a[i+1]=="disable")) emit("package:" clean(a[i+2]),a[i+1],"pm")
                if(cmd=="iptables"||cmd=="ip6tables"||cmd=="nft")emit("netfilter:" cmd,work,cmd)
                if(cmd=="tc"){target="global";for(j=i+1;j<=n;j++)if(a[j]=="dev")target=clean(a[j+1]);emit("tc:" target,work,"tc")}
                if(cmd=="rm")for(j=i+1;j<=n;j++){target=clean(a[j]);if(target~/^\/(system|vendor|product|system_ext|odm|data\/adb|sys|proc\/sys)(\/|$)/)emit("fileop:" target,"remove","rm")}
                if(cmd=="cp"||cmd=="mv"||cmd=="ln"){
                    target="";for(j=i+1;j<=n;j++){token=clean(a[j]);if(token~/^\//)target=token}
                    if(target~/^\/(system|vendor|product|system_ext|odm|data\/adb)(\/|$)/)emit("fileop:" target,cmd,cmd)
                }
                if(cmd=="chmod"||cmd=="chown"){
                    mode=clean(a[i+1]);target="";for(j=i+2;j<=n;j++){token=clean(a[j]);if(token~/^\//)target=token}
                    if(target!="")emit("perm:" target,mode,cmd)
                }
            }
            if(match(work,/>[[:space:]]*\/[^[:space:];&|]+/)){
                target=substr(work,RSTART,RLENGTH);sub(/^>[[:space:]]*/,"",target);target=clean(target)
                before=substr(work,1,RSTART-1);sub(/^[[:space:]]*(echo|printf)[[:space:]]+/,"",before)
                if(target~/^\/sys\//||target~/^\/proc\/sys\//)emit("sysfs:" target,before,"redirect")
            }
        }
        {
            raw=$0; sub(/\r$/, "", raw)
            if(raw ~ /\\[[:space:]]*$/){sub(/\\[[:space:]]*$/, "", raw); pending=pending raw " "; next}
            work=trim(pending raw); pending=""
            if(work==""||work~/^#/)next
            if(work~/^[A-Za-z_][A-Za-z0-9_]*=/ && work !~ /[[:space:]]/){eq=index(work,"=");k=substr(work,1,eq-1);v=clean(substr(work,eq+1));if(isliteral(v))vars[k]=v;next}
            parse(work)
        }
        END{if(pending!="")parse(trim(pending))}
    ' "$file" >> "$SCRIPT_FILE"
}

module_states_json() {
    out=""
    [ -s "$MODULE_STATE_FILE" ] || { printf ''; return; }
    while IFS="$(printf '\t')" read -r id name version state mount_mode root; do
        item="{\"id\":\"$(json_escape "$id")\",\"name\":\"$(json_escape "$name")\",\"version\":\"$(json_escape "$version")\",\"state\":\"$(json_escape "$state")\",\"mount_mode\":\"$(json_escape "$mount_mode")\"}"
        [ -n "$out" ] && out="$out,$item" || out="$item"
    done < "$MODULE_STATE_FILE"
    printf '%s' "$out"
}

prune_history() {
    limit=$(get_config report_history_limit 10)
    case "$limit" in ''|*[!0-9]*) limit=10 ;; esac
    [ "$limit" -gt 0 ] || return
    list="$TMP_DIR/history-list.work"
    find "$HISTORY_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | sort -r > "$list"
    n=0
    while IFS= read -r json; do
        n=$((n+1)); [ "$n" -le "$limit" ] && continue
        base="${json%.json}"
        rm -f "$base.json" "$base.log" "$base.tsv" 2>/dev/null
    done < "$list"
}

