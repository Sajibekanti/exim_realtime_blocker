#!/bin/bash
# ==============================================================================
# Script Name: exim_realtime_blocker.sh
# Description: Monitors Exim mainlog in real-time, registers limit breaches,
#              sends an email alert, and automatically suspends accounts.
# ==============================================================================

# --- Configuration (Adjust as needed) ---
HOURLY_LIMIT=100
STRIKE_DB="/var/log/exim_spam_strikes.db"
LOG_FILE="/var/log/exim_realtime_blocker.log"
ALERT_EMAIL="support@prenhost.com"

# Maintain tracking states
CURRENT_HOUR=$(date +%Y%m%d%H)
touch "$STRIKE_DB"
touch "$LOG_FILE"

log_action() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log_action "INFO: Real-time Anti-Spam Guard Service Init initiated."

# --- Real-Time Log Pipeline Processing ---
tail -Fn0 /var/log/exim_mainlog | while read -r line; do
    
    # Reset strike logs when clock enters a new hour block
    NOW_HOUR=$(date +%Y%m%d%H)
    if [ "$NOW_HOUR" != "$CURRENT_HOUR" ]; then
        echo -n "" > "$STRIKE_DB"
        CURRENT_HOUR="$NOW_HOUR"
        log_action "INFO: New hour boundary detected. Purging tracking database."
    fi

    # Intercept successful incoming authenticated email log lines
    if echo "$line" | grep -q "A=dovecot_login:"; then
        EMAIL_USER=$(echo "$line" | grep -oP 'A=dovecot_login:\K[^ ]+' | head -n 1)
        
        if [ ! -z "$EMAIL_USER" ]; then
            DOMAIN=$(echo "$EMAIL_USER" | cut -d'@' -f2)
            
            # Aggregate total mail vectors emitted in current hour
            CURRENT_COUNT=$(grep -c "<= $EMAIL_USER" /var/log/exim_mainlog)
            
            if [ "$CURRENT_COUNT" -gt "$HOURLY_LIMIT" ]; then
                STRIKES=$(grep "^${DOMAIN}:" "$STRIKE_DB" | cut -d':' -f2)
                
                if [ -z "$STRIKES" ]; then
                    # Strike 1: Registration Entry
                    echo "${DOMAIN}:1" >> "$STRIKE_DB"
                    log_action "WARNING: ${DOMAIN} (${EMAIL_USER}) reached $CURRENT_COUNT emails. Strike 1 registered."
                elif [ "$STRIKES" -eq 1 ]; then
                    # Strike 2: Hard Enforcement Action
                    log_action "CRITICAL: ${DOMAIN} (${EMAIL_USER}) repeated breach ($CURRENT_COUNT emails). Invoking Strike 2 protocols."
                    
                    CP_USER=$(whmapi1 getdomainowner domain="$DOMAIN" 2>/dev/null | awk '/user:/ {print $2}')
                    
                    if [ ! -z "$CP_USER" ]; then
                        
                        # Dispatch Urgent Administrator Email Alert
                        log_action "NOTIFICATION: Sending incident report to $ALERT_EMAIL..."
                        mail_body=$(cat <<EOF
URGENT: WHM Automated Anti-Spam Account Suspension Execution

Infrastructure protection system has frozen a cPanel user account for repeatedly violating outbound volume limit caps within a 60-minute window.

--------------------------------------------------
cPanel Account User: $CP_USER
Primary Flagged Domain: $DOMAIN
Authenticated Mailbox: $EMAIL_USER
Outbound Activity Size: $CURRENT_COUNT messages/hour
Enforcement Action:    Full cPanel Account Suspension
--------------------------------------------------

Investigate system paths for web-shell uploads or mandate a password reset for the compromised credential strings.
EOF
)
                        echo "$mail_body" | mail -s "ALERT: Account Suspended for Mail Spamming [$CP_USER]" "$ALERT_EMAIL"
                        
                        # Suspend full site privileges via WHM Core Engine APIs
                        log_action "SUSPENSION: Locking down cPanel user system rights: $CP_USER..."
                        whmapi1 suspendacct user="$CP_USER" reason="Automated Real-time Anti-Spam Guard: Exceeded hourly mail rules multi-strikes" retainroute=1 >> "$LOG_FILE" 2>&1
                        
                        # Terminate processing sockets
                        systemctl restart exim >/dev/null 2>&1
                        
                        log_action "SUCCESS: Isolation execution finalized for user [${CP_USER}] representing domain [${DOMAIN}]."
                        sed -i "s/^${DOMAIN}:.*/${DOMAIN}:2/" "$STRIKE_DB"
                    else
                        log_action "ERROR: Dynamic query lookup failed mapping owner for domain $DOMAIN."
                    fi
                fi
            fi
        fi
    fi
done
