#!/bin/bash


set -e


declare -r MAX_TIMEOUT=7200 
declare -r MAX_RETRIES=3
declare -r SLEEP_INTERVAL=10


parse_arguments() {

    SINGLE_DOMAIN=""
    DOMAIN_LIST=""
    PROXY=""
    DO_SUBDOMAIN=true
    DO_HTTP=true
    DO_WAYBACK=true
    DO_CRAWL=true
    DO_DIRB=true
    DO_GF=true
    DO_NUCLEI=true
    DO_BURP=true
    DO_NESSUS=false
    NESSUS_USER=""
    NESSUS_PASS=""
    FORCE_RESCAN=false


    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -d)
                if [[ -n "$2" ]]; then
                    SINGLE_DOMAIN="$2"
                    shift 2
                else
                    echo "Error: -d requires a domain argument"
                    exit 1
                fi
                ;;
            -l)
                if [[ -n "$2" ]]; then
                    DOMAIN_LIST="$2"
                    shift 2
                else
                    echo "Error: -l requires a file argument"
                    exit 1
                fi
                ;;
            --skip-subdomain)
                DO_SUBDOMAIN=false
                shift
                ;;
            --skip-http)
                DO_HTTP=false
                shift
                ;;
            --skip-wayback)
                DO_WAYBACK=false
                shift
                ;;
            --skip-crawl)
                DO_CRAWL=false
                shift
                ;;
            --skip-dirb)
                DO_DIRB=false
                shift
                ;;
            --skip-gf)
                DO_GF=false
                shift
                ;;
            --skip-nuclei)
                DO_NUCLEI=false
                shift
                ;;
            --skip-burp)
                DO_BURP=false
                shift
                ;;
            --with-nessus)
                DO_NESSUS=true
                shift
                ;;
            --nessus-user)
                if [[ -n "$2" ]]; then
                    NESSUS_USER="$2"
                    shift 2
                else
                    echo "Error: --nessus-user requires a username argument"
                    exit 1
                fi
                ;;
            --nessus-pass)
                if [[ -n "$2" ]]; then
                    NESSUS_PASS="$2"
                    shift 2
                else
                    echo "Error: --nessus-pass requires a password argument"
                    exit 1
                fi
                ;;
            --force-rescan)
                FORCE_RESCAN=true
                shift
                ;;
            *)
                if [[ -z "$PROXY" ]]; then
                    PROXY="$1"
                    shift
                else
                    echo "Error: Unknown argument: $1"
                    show_usage
                    exit 1
                fi
                ;;
        esac
    done


    if [[ -z "$SINGLE_DOMAIN" ]] && [[ -z "$DOMAIN_LIST" ]]; then
        echo "Error: Either -d <domain> or -l <domain_list> must be specified"
        show_usage
        exit 1
    fi

    if [[ -n "$SINGLE_DOMAIN" ]] && [[ -n "$DOMAIN_LIST" ]]; then
        echo "Error: Cannot specify both -d and -l options"
        show_usage
        exit 1
    fi


    if [[ -z "$PROXY" ]] && [[ "$DO_BURP" = true ]]; then
        echo "Error: Proxy argument is required when Burp integration is enabled"
        show_usage
        exit 1
    fi


    if [[ -n "$PROXY" ]]; then
        if ! echo "$PROXY" | grep -qP '^http(s)?://[a-zA-Z0-9.-]+:[0-9]+$'; then
            echo "Error: Invalid proxy format. Should be http(s)://host:port"
            exit 1
        fi
    fi


    if [[ "$DO_NESSUS" = true ]]; then
        if [[ -z "$NESSUS_USER" ]] || [[ -z "$NESSUS_PASS" ]]; then
            echo "Error: Nessus credentials required when using --with-nessus"
            exit 1
        fi
    fi


    if [[ -n "$DOMAIN_LIST" ]] && [[ ! -f "$DOMAIN_LIST" ]]; then
        echo "Error: Domain list file not found: $DOMAIN_LIST"
        exit 1
    fi


    if [ "$DO_HTTP" = false ]; then
        if [ "$DO_CRAWL" = true ] || [ "$DO_DIRB" = true ]; then
            echo "[!] Warning: Disabling HTTP probe will also affect crawling and directory scanning"
        fi
    fi
    
    if [ "$DO_SUBDOMAIN" = false ]; then
        if [ "$DO_HTTP" = true ] || [ "$DO_WAYBACK" = true ]; then
            echo "[!] Warning: Disabling subdomain enumeration will affect HTTP probe and wayback collection"
        fi
    fi
    
    if [ "$DO_WAYBACK" = false ]; then
        if [ "$DO_GF" = true ]; then
            echo "[!] Warning: Disabling wayback will affect pattern matching"
        fi
    fi

    export SINGLE_DOMAIN DOMAIN_LIST PROXY DO_SUBDOMAIN DO_HTTP DO_WAYBACK DO_CRAWL DO_DIRB DO_GF DO_NUCLEI DO_BURP DO_NESSUS NESSUS_USER NESSUS_PASS FORCE_RESCAN
}


show_usage() {
    cat << EOF
Usage: $0 [options] (-d <domain> | -l <domain_list>) <proxy>

Required arguments:
  -d <domain>           Single domain to scan
  -l <domain_list>      File containing list of domains (one per line)
  <proxy>               Burp Suite proxy URL (http://host:port)

Options:
  -h, --help           Show this help message
  --skip-subdomain     Skip subdomain enumeration phase
  --skip-http          Skip HTTP probe phase
  --skip-wayback       Skip wayback URL collection
  --skip-crawl         Skip crawling with katana
  --skip-dirb          Skip directory bruteforcing with Gobuster
  --skip-gf            Skip pattern matching with gf
  --skip-nuclei        Skip nuclei scanning
  --skip-burp          Skip sending URLs to Burp Suite
  --with-nessus        Enable Nessus integration
  --nessus-user USER   Nessus username (required with --with-nessus)
  --nessus-pass PASS   Nessus password (required with --with-nessus)
  --force-rescan       Force rescan, ignore existing results

Examples:
  Single domain:     $0 -d example.com http://burp:8080
  Multiple domains:  $0 -l domains.txt http://burp:8080
  With options:      $0 -l domains.txt http://burp:8080 --skip-dirb --with-nessus --nessus-user admin --nessus-pass secret
EOF
}


cleanup() {
    local output_dir="$1"
    echo "[*] Performing cleanup..."
    

    rm -f "${output_dir}/gobuster_temp_"* 2>/dev/null || true
    rm -f "${output_dir}/katana_temp_"* 2>/dev/null || true
    rm -f "${output_dir}/tmp_"* 2>/dev/null || true
    rm -f "${output_dir}/*.lock" 2>/dev/null || true
    rm -f "${output_dir}/subdomains1" 2>/dev/null || true
    
    echo "[*] Cleanup completed"
}


check_lock() {
    local lock_file="$1"
    local max_age=${2:-$MAX_TIMEOUT}
    
    if [ -f "$lock_file" ]; then
        local lock_time=$(stat -c %Y "$lock_file" 2>/dev/null || echo 0)
        local current_time=$(date +%s)
        local age=$((current_time - lock_time))
        
        if [ $age -gt $max_age ]; then
            echo "[!] Stale lock found, removing: $lock_file"
            rm -f "$lock_file"
            return 1
        fi
        return 0
    fi
    return 1
}

create_lock() {
    local lock_file="$1"
    echo "[*] Creating lock: $lock_file"
    touch "$lock_file"
}

remove_lock() {
    local lock_file="$1"
    echo "[*] Removing lock: $lock_file"
    rm -f "$lock_file"
}


check_resume() {
    local output_file="$1"
    local min_size="$2"
    local force_rescan="${3:-false}" 
    
    if [ "$force_rescan" = "true" ]; then
        echo "[*] Force rescan enabled, ignoring existing results"
        return 1
    fi
    
    if [ -f "$output_file" ]; then
        local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null)
        if [ -n "$file_size" ] && [ "$file_size" -gt "$min_size" ]; then
            echo "[*] Found existing results in $output_file (size: $file_size bytes)"
            return 0
        else
            echo "[*] Found incomplete or empty results in $output_file"
            return 1
        fi
    fi
    return 1
}


do_subdomain_enum() {
    local domain="$1"
    local output_dir="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/subdomain.lock"
    local final_output="${output_dir}/subdomains"
    local retry_count=0
    

    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing subdomain results from $final_output"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] Subdomain enumeration already in progress"
        return 0
    fi
    
    create_lock "$lock_file"
    
    echo "[+] Starting subdomain enumeration for $domain..."
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        {

            subfinder -d "$domain" -rL dns-resolvers.txt -recursive -o "${output_dir}/subdomains_subfinder" || true
            assetfinder --subs-only "$domain" > "${output_dir}/subdomains_assetfinder" || true
            shuffledns -d "$domain" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
                -r dns-resolvers.txt -mode bruteforce > "${output_dir}/subdomains_shuffledns" || true
            

            cat "${output_dir}/subdomains_"* 2>/dev/null | sort -u > "${output_dir}/subdomains"
            
            if [ -s "${output_dir}/subdomains" ]; then
                echo "[+] Found $(wc -l < "${output_dir}/subdomains") unique subdomains"
                break
            else
                ((retry_count++))
                echo "[!] No subdomains found, retrying ($retry_count/$MAX_RETRIES)..."
            fi
        } || {
            echo "[-] Error in subdomain enumeration iteration $retry_count"
            ((retry_count++))
        }
    done
    
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] Subdomain enumeration failed after $MAX_RETRIES attempts"
        return 1
    fi
}


do_http_probe() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/httpx.lock"
    local final_output="${output_dir}/httpx"
    local retry_count=0
    

    if check_resume "$final_output" 50 "$force_rescan"; then
        echo "[+] Using existing HTTP probe results from $final_output"
        return 0
    fi
    

    if ! [ -f "${output_dir}/subdomains" ]; then
        echo "[-] Subdomain file not found"
        return 1
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] HTTP probing already in progress or completed"
        return 0
    fi
    
    create_lock "$lock_file"
    retry_count=0
    
    echo "[+] Starting HTTP probe..."
    local common_ports="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        local httpx_cmd="httpx -silent -no-color -random-agent -ports \"$common_ports\" -timeout 10"
        

        if [ "$DO_BURP" = true ] && [ -n "$PROXY" ]; then
            httpx_cmd="$httpx_cmd -proxy $PROXY"
        fi
        
        if cat "${output_dir}/subdomains" | eval "$httpx_cmd" > "${output_dir}/httpx"; then
            if [ -s "${output_dir}/httpx" ]; then
                echo "[+] Found $(wc -l < "${output_dir}/httpx") live HTTP endpoints"
                break
            fi
        fi
        
        ((retry_count++))
        echo "[!] HTTP probe failed or no results, retrying ($retry_count/$MAX_RETRIES)..."
    done
    
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] HTTP probe failed after $MAX_RETRIES attempts"
        return 1
    fi
}


do_wayback() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/wayback.lock"
    local final_output="${output_dir}/waybacksorted"
    local retry_count=0
    

    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing wayback results from $final_output"
        return 0
    fi
    

    if ! [ -f "${output_dir}/subdomains" ]; then
        echo "[-] Subdomain file not found"
        return 1
    fi
    
    if check_lock "$lock_file"; then
        return 0
    fi
    
    create_lock "$lock_file"
    retry_count=0
    
    echo "[+] Starting wayback URL collection..."
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if cat "${output_dir}/subdomains" | waybackurls > "${output_dir}/waybackdata_tmp"; then
            if [ -s "${output_dir}/waybackdata_tmp" ]; then
                sort -u "${output_dir}/waybackdata_tmp" > "${output_dir}/waybacksorted"
                echo "[+] Collected $(wc -l < "${output_dir}/waybacksorted") unique URLs from wayback"
                break
            fi
        fi
        
        ((retry_count++))
        echo "[!] Wayback collection failed or no results, retrying ($retry_count/$MAX_RETRIES)..."
    done
    
    rm -f "${output_dir}/waybackdata_tmp"
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] Wayback collection failed after $MAX_RETRIES attempts"
        return 1
    fi
}


do_gf_patterns() {
    local domain="$1"
    local output_dir="$2"
    local proxy="$3"
    local force_rescan="${4:-false}"
    local lock_file="${output_dir}/gf.lock"
    local final_output="${output_dir}/gfcikti"
    
    # Resume kontrolü
    if check_resume "$final_output" 50 "$force_rescan"; then
        echo "[+] Using existing pattern matching results from $final_output"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        return 0
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting GF pattern matching..."
    
    patterns=("ssrf" "rce" "redirect" "sqli" "lfi" "ssti" "xss" "interestingEXT" "debug_logic")
    

    : > "${output_dir}/gfcikti"

    for pattern in "${patterns[@]}"; do
        echo "[+] Scanning for $pattern in $domain..."
        if [ -f "${output_dir}/waybacksorted" ]; then
            local httpx_cmd="httpx -mc 200,202,201 -silent"
            
            if [ "$DO_BURP" = true ] && [ -n "$proxy" ]; then
                httpx_cmd="$httpx_cmd -proxy $proxy"
            fi
            
            cat "${output_dir}/waybacksorted" | \
                gf "$pattern" 2>/dev/null | \
                grep -viE '(\.(js|css|svg|png|jpg|woff))' | \
                qsreplace -a 2>/dev/null | \
                eval "$httpx_cmd" 2>/dev/null | \
                awk '{ print $1}' >> "${output_dir}/gfcikti" || true
        fi
    done

    echo "[+] Pattern matching completed"
    remove_lock "$lock_file"
}


do_nuclei_scans() {
    local domain="$1"
    local output_dir="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/nuclei.lock"
    local dast_output="${output_dir}/fuzzing_dast"
    local httpx_output="${output_dir}/nucleihttpx"
    local subs_output="${output_dir}/nucleisubs"
    

    local resume=true
    if ! check_resume "$dast_output" 50 "$force_rescan"; then
        resume=false
    fi
    if ! check_resume "$httpx_output" 50 "$force_rescan"; then
        resume=false
    fi
    if ! check_resume "$subs_output" 50 "$force_rescan"; then
        resume=false
    fi
    
    if [ "$resume" = true ]; then
        echo "[+] Using existing Nuclei scan results"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] Nuclei scanning already in progress or completed"
        return 0
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting Nuclei scans..."
    

    if [ -f "${output_dir}/gfcikti" ]; then
        echo "[+] Running Nuclei DAST scan on pattern matches..."
        nuclei -list "${output_dir}/gfcikti" \
               -dast \
               -rl 3 \
               -o "${output_dir}/fuzzing_dast" || true
    fi
    

    if [ -f "${output_dir}/httpx" ]; then
        echo "[+] Running Nuclei scan on live HTTP endpoints..."
        nuclei -l "${output_dir}/httpx" \
               -rl 3 \
               -o "${output_dir}/nucleihttpx" || true
    fi
    

    if [ -f "${output_dir}/subdomains" ]; then
        echo "[+] Running Nuclei scan on subdomains..."
        nuclei -l "${output_dir}/subdomains" \
               -sa \
               -rl 3 \
               -o "${output_dir}/nucleisubs" || true
    fi
    
    remove_lock "$lock_file"
    echo "[+] Nuclei scans completed"
}


do_directory_scan() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/gobuster.lock"
    local final_output="${output_dir}/gobuster_results"
    local retry_count=0
    

    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing directory scan results from $final_output"
        return 0
    fi
    
    if [ ! -f "${output_dir}/httpx" ]; then
        echo "[-] HTTP endpoints file not found"
        return 1
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting directory scanning with gobuster..."
    

    local temp_results="${output_dir}/gobuster_temp_results"
    : > "$temp_results"
    
    while read -r url; do
        echo "[+] Scanning directories for: $url"
        
        if ! gobuster dir \
            -u "$url" \
            -w /usr/share/wordlists/dirb/common.txt \
            -t 50 \
            -o "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" \
            -q \
            --no-error \
            -k 2>/dev/null; then
            echo "[-] Gobuster scan failed for $url"
            continue
        fi
        
        if [ -f "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" ]; then
            cat "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" >> "$temp_results"
            rm -f "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}"
        fi
        
    done < "${output_dir}/httpx"
    
    if [ -s "$temp_results" ]; then
        echo "[+] Directory scanning completed successfully"
        mv "$temp_results" "${output_dir}/gobuster_results"
        echo "[+] Found $(wc -l < "${output_dir}/gobuster_results") directories"
    else
        echo "[-] No directories found"
        rm -f "$temp_results"
    fi
    
    remove_lock "$lock_file"
}


do_katana_crawl() {
    local output_dir="$1"
    local proxy="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/katana.lock"
    local final_output="${output_dir}/katana_results"
    local retry_count=0
    

    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing Katana results from $final_output"
        return 0
    fi
    
    if [ ! -f "${output_dir}/httpx" ]; then
        echo "[-] HTTP endpoints file not found"
        return 1
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting Katana crawling..."
    

    local temp_results="${output_dir}/katana_temp_results"
    : > "$temp_results"
    
    while read -r url; do
        echo "[+] Crawling: $url"
        
        local katana_cmd="katana -u $url -silent -jc -kf -aff -d 3 -ct 60 -rl 100 -o ${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}"
        
        if [ "$DO_BURP" = true ] && [ -n "$proxy" ]; then
            katana_cmd="$katana_cmd -proxy $proxy"
        fi
        
        if ! eval "$katana_cmd" 2>/dev/null; then
            echo "[-] Katana crawl failed for $url"
            continue
        fi
        
        if [ -f "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}" ]; then
            cat "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}" >> "$temp_results"
            rm -f "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}"
        fi
        
    done < "${output_dir}/httpx"
    
    if [ -s "$temp_results" ]; then
        echo "[+] Crawling completed successfully"
        sort -u "$temp_results" > "${output_dir}/katana_results"
        echo "[+] Found $(wc -l < "${output_dir}/katana_results") unique URLs"
        rm -f "$temp_results"
    else
        echo "[-] No URLs found during crawling"
        rm -f "$temp_results"
    fi
    
    remove_lock "$lock_file"
}


do_nessus_scan() {
    local domain="$1"
    local output_dir="$2"
    local nessus_user="$3"
    local nessus_pass="$4"
    local lock_file="${output_dir}/nessus.lock"
    local retry_count=0
    
    if check_lock "$lock_file"; then
        echo "[*] Nessus scanning already in progress or completed"
        return 0
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting Nessus scan for $domain..."
    

    local nessus_url="https://localhost:8834"
    

    local token=$(curl -k -s -X POST -H "Content-Type: application/json" \
        -d "{\"username\":\"$nessus_user\",\"password\":\"$nessus_pass\"}" \
        "$nessus_url/session" | jq -r '.token')
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        echo "[-] Failed to authenticate with Nessus"
        remove_lock "$lock_file"
        return 1
    fi
    

    local scan_data=$(curl -k -s -X POST -H "X-Cookie: token=$token" \
        -H "Content-Type: application/json" \
        -d "{\"uuid\":\"731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65\",\"settings\":{\"name\":\"$domain Scan\",\"text_targets\":\"$domain\"}}" \
        "$nessus_url/scans")
    
    local scan_id=$(echo "$scan_data" | jq -r '.scan.id')
    
    if [ -z "$scan_id" ] || [ "$scan_id" = "null" ]; then
        echo "[-] Failed to create Nessus scan"
        remove_lock "$lock_file"
        return 1
    fi
    

    curl -k -s -X POST -H "X-Cookie: token=$token" \
        "$nessus_url/scans/$scan_id/launch" > /dev/null
    
    echo "[+] Nessus scan started with ID: $scan_id"
    

    while true; do
        local status=$(curl -k -s -X GET -H "X-Cookie: token=$token" \
            "$nessus_url/scans/$scan_id" | jq -r '.info.status')
        
        if [ "$status" = "completed" ]; then
            break
        elif [ "$status" = "error" ]; then
            echo "[-] Nessus scan failed"
            remove_lock "$lock_file"
            return 1
        fi
        
        echo "[*] Scan in progress... Status: $status"
        sleep 30
    done
    

    local export_data=$(curl -k -s -X POST -H "X-Cookie: token=$token" \
        -H "Content-Type: application/json" \
        -d '{"format":"html","chapters":"vuln_hosts_summary"}' \
        "$nessus_url/scans/$scan_id/export")
    
    local file_id=$(echo "$export_data" | jq -r '.file')
    
    if [ -n "$file_id" ] && [ "$file_id" != "null" ]; then
        curl -k -s -X GET -H "X-Cookie: token=$token" \
            "$nessus_url/scans/$scan_id/export/$file_id/download" \
            > "${output_dir}/nessus_report.html"
        echo "[+] Nessus scan results saved to: ${output_dir}/nessus_report.html"
    fi
    

    curl -k -s -X DELETE -H "X-Cookie: token=$token" "$nessus_url/session" > /dev/null
    
    remove_lock "$lock_file"
}


merge_results() {
    local output_dir="$1"
    local domain="$2"
    
    echo "[+] Merging all results for $domain..."
    

    local merged_dir="${output_dir}/merged_results"
    mkdir -p "$merged_dir"
    

    {
        [ -f "${output_dir}/httpx" ] && cat "${output_dir}/httpx"
        [ -f "${output_dir}/waybacksorted" ] && cat "${output_dir}/waybacksorted"
        [ -f "${output_dir}/katana_results" ] && cat "${output_dir}/katana_results"
        [ -f "${output_dir}/gobuster_results" ] && cat "${output_dir}/gobuster_results"
    } | sort -u > "${merged_dir}/all_urls.txt"
    

    {
        [ -f "${output_dir}/nucleihttpx" ] && cat "${output_dir}/nucleihttpx"
        [ -f "${output_dir}/nucleisubs" ] && cat "${output_dir}/nucleisubs"
        [ -f "${output_dir}/fuzzing_dast" ] && cat "${output_dir}/fuzzing_dast"
        [ -f "${output_dir}/gfcikti" ] && cat "${output_dir}/gfcikti"
    } > "${merged_dir}/all_findings.txt"
    

    {
        echo "# Scan Results for $domain"
        echo "## Summary"
        echo "- Scan Date: $(date)"
        echo "- Target Domain: $domain"
        echo
        echo "## Statistics"
        [ -f "${output_dir}/subdomains" ] && echo "- Total Subdomains: $(wc -l < "${output_dir}/subdomains")"
        [ -f "${merged_dir}/all_urls.txt" ] && echo "- Total Unique URLs: $(wc -l < "${merged_dir}/all_urls.txt")"
        [ -f "${merged_dir}/all_findings.txt" ] && echo "- Total Security Findings: $(wc -l < "${merged_dir}/all_findings.txt")"
        echo
        echo "## Detailed Results"
        echo "All detailed results can be found in the following files:"
        echo "- All URLs: merged_results/all_urls.txt"
        echo "- All Security Findings: merged_results/all_findings.txt"
        [ -f "${output_dir}/nessus_report.html" ] && echo "- Nessus Scan Report: nessus_report.html"
    } > "${output_dir}/SUMMARY.md"
    
    echo "[+] Results merged successfully"
    echo "[+] Summary report created at: ${output_dir}/SUMMARY.md"
}


check_dependencies() {
    local output_dir="$1"
    local module="$2"
    
    case "$module" in
        "http")
            if [ "$DO_SUBDOMAIN" = false ] && [ ! -f "${output_dir}/subdomains" ]; then
                echo "[-] Error: HTTP probe requires subdomain enumeration results"
                echo "[-] Either run with subdomain enumeration or provide a subdomains file"
                return 1
            fi
            ;;
        "wayback")
            if [ "$DO_SUBDOMAIN" = false ] && [ ! -f "${output_dir}/subdomains" ]; then
                echo "[-] Error: Wayback requires subdomain enumeration results"
                echo "[-] Either run with subdomain enumeration or provide a subdomains file"
                return 1
            fi
            ;;
        "crawl")
            if [ "$DO_HTTP" = false ] && [ ! -f "${output_dir}/httpx" ]; then
                echo "[-] Error: Katana crawling requires HTTP probe results"
                echo "[-] Either run with HTTP probe or provide an httpx file"
                return 1
            fi
            ;;
        "dirb")
            if [ "$DO_HTTP" = false ] && [ ! -f "${output_dir}/httpx" ]; then
                echo "[-] Error: Directory scanning requires HTTP probe results"
                echo "[-] Either run with HTTP probe or provide an httpx file"
                return 1
            fi
            ;;
        "gf")
            if [ "$DO_WAYBACK" = false ] && [ ! -f "${output_dir}/waybacksorted" ]; then
                echo "[-] Error: Pattern matching requires wayback results"
                echo "[-] Either run with wayback or provide a waybacksorted file"
                return 1
            fi
            ;;
        "nuclei")
            local can_run=false
            if [ -f "${output_dir}/gfcikti" ] || [ -f "${output_dir}/httpx" ] || [ -f "${output_dir}/subdomains" ]; then
                can_run=true
            fi
            if [ "$can_run" = false ]; then
                echo "[-] Error: Nuclei requires at least one of: GF results, HTTP probe results, or subdomains"
                return 1
            fi
            ;;
    esac
    return 0
}


scan_domain() {
    local domain="$1"
    local proxy="$2"
    local output_dir="${domain}.monascanner"
    local skip_error=false
    
    if [ -d "$output_dir" ] && [ "$FORCE_RESCAN" = false ]; then
        echo "[*] Found existing scan directory: $output_dir"
        echo "[*] Using existing results where available (use --force-rescan to ignore)"
    fi
    
    mkdir -p "$output_dir" || { echo "Error: Could not create output directory"; return 1; }
    
    trap 'cleanup "$output_dir"' EXIT INT TERM
    
    echo "[+] Starting comprehensive scan for domain: $domain"
    echo "[+] Output directory: $output_dir"
    

    if [ "$DO_SUBDOMAIN" = true ]; then
        echo "[+] Starting subdomain enumeration..."
        if ! do_subdomain_enum "$domain" "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] Subdomain enumeration failed, but continuing with available results..."
        fi
    else
        echo "[*] Skipping subdomain enumeration (--skip-subdomain specified)"
    fi
    

    if [ "$DO_HTTP" = true ]; then
        if ! check_dependencies "$output_dir" "http"; then
            if [ "$DO_SUBDOMAIN" = false ]; then
                echo "[!] HTTP probe will be skipped due to missing dependencies"
                DO_HTTP=false
                skip_error=true
            fi
        fi
    fi
    

    if [ "$DO_WAYBACK" = true ]; then
        if ! check_dependencies "$output_dir" "wayback"; then
            if [ "$DO_SUBDOMAIN" = false ]; then
                echo "[!] Wayback will be skipped due to missing dependencies"
                DO_WAYBACK=false
                skip_error=true
            fi
        fi
    fi
    

    if [ "$DO_DIRB" = true ]; then
        echo "[+] Starting directory scanning..."
        if ! do_directory_scan "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] Directory scanning failed, but continuing..."
        fi
    else
        echo "[*] Skipping directory scanning (--skip-dirb specified)"
    fi
    

    if [ "$DO_GF" = true ]; then
        echo "[+] Starting pattern matching..."
        if ! check_dependencies "$output_dir" "gf"; then
            if [ "$DO_WAYBACK" = false ]; then
                echo "[!] Pattern matching will be skipped due to missing dependencies"
                DO_GF=false
                skip_error=true
            fi
        fi
    else
        echo "[*] Skipping pattern matching (--skip-gf specified)"
    fi
    

    if [ "$DO_CRAWL" = true ]; then
        if ! check_dependencies "$output_dir" "crawl"; then
            if [ "$DO_HTTP" = false ]; then
                echo "[!] Crawling will be skipped due to missing dependencies"
                DO_CRAWL=false
                skip_error=true
            fi
        fi
    fi
    

    if [ "$DO_NUCLEI" = true ]; then
        if ! check_dependencies "$output_dir" "nuclei"; then
            echo "[!] Nuclei scanning will be skipped due to missing dependencies"
            DO_NUCLEI=false
            skip_error=true
        fi
    fi
    

    if [ "$skip_error" = true ]; then
        echo "[!] Some modules were automatically disabled due to missing dependencies"
        echo "[!] Check the messages above for details"
    fi
    

    if [ "$DO_NESSUS" = true ]; then
        echo "[+] Starting Nessus scan..."
        if ! do_nessus_scan "$domain" "$output_dir" "$NESSUS_USER" "$NESSUS_PASS"; then
            echo "[-] Nessus scan failed, but continuing..."
        fi
    else
        echo "[*] Skipping Nessus scan (--with-nessus not specified)"
    fi
    

    merge_results "$output_dir" "$domain"
    
    echo "[+] All scans completed for $domain!"
    echo "[+] Results are saved in: $output_dir"
    echo "[+] Check SUMMARY.md for a complete overview of the results"
    return 0
}

check_requirements() {
    echo "[*] Checking required tools..."
    
    local required_tools=(
        "subfinder"
        "assetfinder"
        "shuffledns"
        "httpx"
        "waybackurls"
        "gobuster"
        "gf"
        "qsreplace"
        "nuclei"
        "curl"
        "katana"
        "jq"
    )
    
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            echo "[-] Missing required tool: $tool"
        else
            echo "[+] Found required tool: $tool"
        fi
    done
    
    if [ ! -f "dns-resolvers.txt" ]; then
        echo "[-] Missing dns-resolvers.txt file"
        missing_tools+=("dns-resolvers.txt")
    fi
    

    if [ ! -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" ]; then
        echo "[-] Missing SecLists DNS wordlist"
        missing_tools+=("seclists")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "\n[-] Missing required tools. Please install them using:"
        echo "----------------------------------------------------"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "subfinder")
                    echo "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
                    ;;
                "assetfinder")
                    echo "go install github.com/tomnomnom/assetfinder@latest"
                    ;;
                "shuffledns")
                    echo "GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
                    ;;
                "httpx")
                    echo "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
                    ;;
                "waybackurls")
                    echo "go install github.com/tomnomnom/waybackurls@latest"
                    ;;
                "gobuster")
                    echo "go install github.com/OJ/gobuster/v3@latest"
                    ;;
                "gf")
                    echo "go install github.com/tomnomnom/gf@latest"
                    ;;
                "qsreplace")
                    echo "go install github.com/tomnomnom/qsreplace@latest"
                    ;;
                "nuclei")
                    echo "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
                    ;;
                "katana")
                    echo "GO111MODULE=on go install github.com/projectdiscovery/katana/cmd/katana@latest"
                    ;;
                "dns-resolvers.txt")
                    echo "wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O dns-resolvers.txt"
                    ;;
                "seclists")
                    echo "sudo apt install seclists # For Debian/Ubuntu"
                    echo "# OR"
                    echo "git clone https://github.com/danielmiessler/SecLists.git"
                    ;;
                "jq")
                    echo "sudo apt install jq # For Debian/Ubuntu"
                    echo "# OR"
                    echo "brew install jq # For macOS"
                    ;;
            esac
        done
        echo "----------------------------------------------------"
        echo "After installing, make sure all tools are in your PATH"
        exit 1
    fi
    
    echo "[+] All required tools are installed!"
}

validate_url() {
    local url="$1"
    if [[ "$url" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

main() {
    parse_arguments "$@"
    check_requirements
    
    if [ -n "$SINGLE_DOMAIN" ]; then
        scan_domain "$SINGLE_DOMAIN" "$PROXY"
    elif [ -n "$DOMAIN_LIST" ]; then
        while IFS= read -r domain || [ -n "$domain" ]; do
            if [ -n "$domain" ] && [[ ! "$domain" =~ ^[[:space:]]*# ]]; then
                domain=$(echo "$domain" | tr -d '[:space:]')
                if validate_url "$domain"; then
                    scan_domain "$domain" "$PROXY"
                else
                    echo "[-] Invalid domain format, skipping: $domain"
                fi
            fi
        done < "$DOMAIN_LIST"
    fi
    
    echo "[+] All scanning operations completed successfully!"
}

main "$@"


