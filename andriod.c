#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <time.h>
#include <jansson.h>
#include <dirent.h>

#define BLE_SCAN_DURATION 5
#define CVE_DIR "/home/kali/Desktop/coding/cve/cve_data"
  // Adjust path as needed

void trim_whitespace(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t' || str[len - 1] == '\n')) {
        str[len - 1] = '\0';
        len--;
    }
}

int supports_ble() {
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        return 0;
    }

    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        return 0;
    }

    struct hci_dev_info dev_info;
    memset(&dev_info, 0, sizeof(dev_info));
    dev_info.dev_id = dev_id;
    if (ioctl(sock, HCIGETDEVINFO, (void *)&dev_info) < 0) {
        close(sock);
        return 0;
    }

    close(sock);
    return (dev_info.features[4] & 0x40) != 0;
}

void query_extended_sdp_services(bdaddr_t bdaddr, int *a2dp, int *map, int *pbap, int *hfp, int *opp) {
    *a2dp = *map = *pbap = *hfp = *opp = 0;
    sdp_session_t *session = sdp_connect(BDADDR_ANY, &bdaddr, SDP_RETRY_IF_BUSY);
    if (!session) {
        perror("Failed to connect to SDP session");
        return;
    }

    uint16_t uuids[] = { 0x110D, 0x1132, 0x112F, 0x111E, 0x1105 };
    int *flags[] = { a2dp, map, pbap, hfp, opp };

    for (int i = 0; i < 5; i++) {
        uuid_t uuid;
        sdp_uuid16_create(&uuid, uuids[i]);
        sdp_list_t *search_list = sdp_list_append(NULL, &uuid);
        uint32_t range = 0x0000ffff;
        sdp_list_t *attrid_list = sdp_list_append(NULL, &range);

        sdp_list_t *rsp_list = NULL;
        if (sdp_service_search_attr_req(session, search_list, SDP_ATTR_REQ_RANGE, attrid_list, &rsp_list) == 0) {
            if (rsp_list) {
                *flags[i] = 1;
                sdp_list_free(rsp_list, (sdp_free_func_t)sdp_record_free);
            }
        }

        sdp_list_free(search_list, NULL);
        sdp_list_free(attrid_list, NULL);
    }

    sdp_close(session);
}

int get_lmp_version(bdaddr_t *bdaddr) {
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        return -1;
    }

    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        return -1;
    }

    int acl_sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (acl_sock < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_l2 addr = { 0 };
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(0x0001);
    addr.l2_bdaddr = *bdaddr;

    if (connect(acl_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(acl_sock);
        close(sock);
        return -1;
    }

    struct hci_conn_info_req *cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
    if (!cr) {
        fprintf(stderr, "Failed to allocate memory\n");
        close(acl_sock);
        close(sock);
        return -1;
    }
    bacpy(&cr->bdaddr, bdaddr);
    cr->type = ACL_LINK;

    if (ioctl(sock, HCIGETCONNINFO, (void *) cr) < 0) {
        free(cr);
        close(acl_sock);
        close(sock);
        return -1;
    }

    int handle = cr->conn_info->handle;
    free(cr);

    struct hci_version ver;
    if (hci_read_remote_version(sock, handle, &ver, 1000) < 0) {
        close(acl_sock);
        close(sock);
        return -1;
    }

    close(acl_sock);
    close(sock);

    return ver.lmp_ver;
}

const char* estimate_version_score(
    int lmp, int a2dp, int map, int pbap, int hfp, int opp, int ble_supported)
{
    if (lmp >= 9 && ble_supported && (a2dp || hfp) && !map && !pbap)
        return "Non-Android Device";

    int score = 0;
 
    if (lmp >= 13)       score += 98;
    else if (lmp == 12)  score += 88;
    else if (lmp == 11)  score += 78;
    else if (lmp == 10)  score += 68;
    else if (lmp == 9)   score += 85;
    else if (lmp == 8)   score += 48;
    else if (lmp == 7)   score += 25;
    else if (lmp == 6)   score += 15;
    else if (lmp == 5)   score += 10;
    else if (lmp == 4)   score += 5;
    else                 score += 0;

    if (a2dp) score += 1;
    if (hfp)  score += 1;
    if (opp)  score += 1;

    if (map) {
        if (lmp >= 8) score += 1;
        else if (lmp >= 7) score += 0; 
        else score += 0;
    }
    if (pbap) {
        if (lmp >= 8) score += 1;
        else if (lmp >= 7) score += 0; 
        else score += 0;
    }
    
    if (ble_supported) {
        if (lmp >= 9) score += 1;
        else if (lmp >= 8) score += 1;
        else if (lmp >= 7) score += 0; 
        else score += 0;
    }

    if (lmp >= 12 && a2dp && map && pbap && hfp && opp && ble_supported)
        score += 1;
    else if (lmp >= 10 && a2dp && map && pbap && hfp && opp)
        score += 1;

    float weighted_score = (score / 105.0f) * 10.0f;
    printf("→ Weighted Score: %.2f\n", weighted_score);

    if (weighted_score >= 9.2)
        return "Android 15 (Vanilla Ice Cream)";
    else if (weighted_score >= 8.2)
        return "Android 14 (Upside Down Cake)";
    else if (weighted_score >= 7.2)
        return "Android 13 (Tiramisu)";
    else if (weighted_score >= 7.15)
        return "Android 12 (Snow Cone)";
    else if (weighted_score >= 7.0)
        return "Android 11 (Red Velvet Cake)";
    else if (weighted_score >= 4.0)
        return "Android 10 (Q)";
    else if (weighted_score >= 3.5)
        return "Android 9.0 (Pie)";
    else if (weighted_score >= 3.0)
        return "Android 8.0/8.1 (Oreo)";
    else if (weighted_score >= 2.7)
        return "Android 7.0/7.1 (Nougat)";
    else if (weighted_score >= 2.68)
        return "Android 6.0 (Marshmallow)";
    else if (weighted_score >= 1.9)
        return "Android 5.1/5.1.1 (Lollipop MR1)";
    else if (weighted_score >= 1.0)
        return "Android 5.0 (Lollipop)";
    else if (weighted_score >= 0.8)
        return "Android 4.4 (KitKat)";
    else if (weighted_score >= 0.6)
        return "Android 4.0–4.3 (ICS / JB)";
    else if (weighted_score >= 0.4)
        return "Android 3.x (Honeycomb)";
    else if (weighted_score >= 0.2)
        return "Android 2.3 (Gingerbread)";
    else if (weighted_score >= 0.1)
        return "Android 2.2 (Froyo)";
    else if (weighted_score >= 0.05)
        return "Android 2.0 (Eclair)";
    else if (weighted_score >= 0.03)
        return "Android 1.6 (Donut)";
    else if (weighted_score >= 0.01)
        return "Android 1.5 (Cupcake)";
    else if (weighted_score >= 0.001)
        return "Android 1.0 (Base)";
    else
        return "Unknown Android Version";
}

void search_cves_by_keyword(const char *keyword) {
    DIR *d;
    struct dirent *dir;
    char filepath[512];

    d = opendir(CVE_DIR);
    if (!d) {
        fprintf(stderr, "Failed to open CVE directory: %s\n", strerror(errno));
        return;
    }

    int found = 0;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type != DT_REG) continue;
        if (strstr(dir->d_name, ".json") == NULL) continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", CVE_DIR, dir->d_name);
        FILE *f = fopen(filepath, "r");
        if (!f) continue;

        json_error_t error;
        json_t *root = json_loadf(f, 0, &error);
        fclose(f);
        if (!root) continue;

        json_t *cve_items = json_object_get(root, "CVE_Items");
        if (!cve_items || !json_is_array(cve_items)) {
            json_decref(root);
            continue;
        }

        size_t index;
        json_t *item;
        for (index = 0; index < json_array_size(cve_items); index++) {
            item = json_array_get(cve_items, index);
            if (!json_is_object(item)) continue;

            json_t *cve = json_object_get(item, "cve");
            if (!cve) continue;
            json_t *desc = json_object_get(cve, "description");
            if (!desc) continue;
            json_t *desc_data = json_object_get(desc, "description_data");
            if (!desc_data || !json_is_array(desc_data)) continue;
            json_t *desc_obj = json_array_get(desc_data, 0);
            if (!desc_obj) continue;
            json_t *value = json_object_get(desc_obj, "value");
            if (!value || !json_is_string(value)) continue;

            const char *desc_str = json_string_value(value);
            if (desc_str && strcasestr(desc_str, keyword)) {
                json_t *meta = json_object_get(cve, "CVE_data_meta");
                if (!meta) continue;
                json_t *id = json_object_get(meta, "ID");
                if (!id || !json_is_string(id)) continue;

                printf("CVE ID: %s\nDescription: %s\n\n", json_string_value(id), desc_str);
                found = 1;
            }
        }

        json_decref(root);
    }

    closedir(d);
    if (!found) {
        printf("→ No relevant CVEs found for '%s'\n", keyword);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Bluetooth MAC address>\n", argv[0]);
        return 1;
    }

    bdaddr_t bdaddr;
    if (str2ba(argv[1], &bdaddr) < 0) {
        fprintf(stderr, "Invalid Bluetooth MAC address format.\n");
        return 1;
    }

    printf("[*] Querying extended SDP services...\n");
    int a2dp, map, pbap, hfp, opp;
    query_extended_sdp_services(bdaddr, &a2dp, &map, &pbap, &hfp, &opp);

    int lmp_version = get_lmp_version(&bdaddr);
    if (lmp_version < 0) {
        fprintf(stderr, "Failed to get LMP version.\n");
        return 1;
    }
    printf("[*] LMP version detected: %d\n", lmp_version);

    int ble_supported = supports_ble();
    printf("[*] Local adapter supports BLE: %s\n", ble_supported ? "Yes" : "No");

    const char *estimation = estimate_version_score(lmp_version, a2dp, map, pbap, hfp, opp, ble_supported);

    printf("\n===== Bluetooth Device Estimation =====\n");
    printf("LMP Version: %d\n", lmp_version);
    printf("A2DP: %s\n", a2dp ? "Present" : "Absent");
    printf("MAP: %s\n", map ? "Present" : "Absent");
    printf("PBAP: %s\n", pbap ? "Present" : "Absent");
    printf("HFP: %s\n", hfp ? "Present" : "Absent");
    printf("OPP: %s\n", opp ? "Present" : "Absent");
    printf("BLE Support: %s\n", ble_supported ? "Yes" : "No");
    printf("Estimated Device Type/Android Version: %s\n\n", estimation);

    // Strip parentheses and trailing whitespace for CVE search keyword
    char cve_keyword[100];
    strncpy(cve_keyword, estimation, sizeof(cve_keyword));
    cve_keyword[sizeof(cve_keyword) - 1] = '\0';

    char *paren = strchr(cve_keyword, '(');
    if (paren) *paren = '\0';
    trim_whitespace(cve_keyword);

    printf("[*] Looking up CVEs related to %s...\n", cve_keyword);
    search_cves_by_keyword(cve_keyword);

    return 0;
}