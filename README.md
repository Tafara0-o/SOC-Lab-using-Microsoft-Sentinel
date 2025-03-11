

# **Azure Honeypot & Log Analysis - Step-by-Step Walkthrough**

## **Introduction**

This guide details how I set up an **Azure Virtual Machine (VM) Honeypot**, configured **log forwarding** to Microsoft Sentinel, and analyzed security logs using **KQL queries**. I am following the walkthrough by Josh Madakor (https://youtu.be/g5JL2RIbThM)

 **Key Concepts Covered:**

-   Creating an **Azure Subscription**
-   Deploying a **Windows 10 Virtual Machine (VM) Honeypot**
-   Configuring **Log Analytics & Microsoft Sentinel**
-   Querying logs with **KQL (Kusto Query Language)**
-   Enriching logs with **GeoIP data**
-   Creating a **real-time attack map**

 **Resources Used:**

-   **Azure Free/Paid Subscription**: [Sign up for Azure](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account)
-   **Cyber Range (Optional - Provides Paid Azure Access & Training)**: [Join Cyber Range](https://skool.com/cyber-range)
-   **Free Cybersecurity Training**: [KC7 Cyber Range](https://kc7cyber.com/)

----------

## **Part 1: Setup Azure Subscription**

### **Step 1: Create an Azure Subscription**

I attempted to sign up for **Azure’s Free Tier** via [Azure Free Tier](https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account), but if the free tier is unavailable, you have two options:

1.  **Create a Pay-As-You-Go Subscription** _(What I did - just be mindful of shutting down/deleting resources to avoid unnecessary charges)_.
2.  **Join the Cyber Range** _(If you have the money, this is a great alternative since it provides full Azure access, labs, and training at a flat fee - [Cyber Range](https://skool.com/cyber-range))_

### **Step 2: Log in to Azure**

 **Azure Portal**: [https://portal.azure.com](https://portal.azure.com/)

----------

## **Part 2: Deploying the Honeypot (Azure Virtual Machine)**

### **Step 1: Create a Windows 10 Virtual Machine**

1.  Navigate to [Azure Portal](https://portal.azure.com/).
2.  Search for **"Virtual Machines"** and click **Create New VM**.
3.  Select **Windows 10** as the OS.
4.  Choose an appropriate VM size _(If you're in Cyber Range, the size will be limited)_.
5.  **Set a username & password** _(Store securely!)_

![Screenshot 2025-02-18 165439](https://github.com/user-attachments/assets/f5d5393a-0110-46c0-ac0b-9203011ffa6a)


### **Step 2: Configure Network Security Group (NSG) Rules**

1.  Open your **Virtual Machine → Networking → Network Security Group**.
2.  Create a new **Inbound Rule**:
    -   **Protocol:** Any
    -   **Port:** Any
    -   **Action:** **Allow All Traffic** _(Simulates an exposed system)_


### **Step 3: Disable Windows Firewall**

1.  Log into the VM via **Remote Desktop (RDP)**.
2.  Open **Run (`Win + R`) → Type `wf.msc` → Enter**.
3.  **Disable** all firewall profiles _(Domain, Private, Public)_.

![Screenshot 2025-02-18 181033](https://github.com/user-attachments/assets/d043e50e-96ff-4119-a8fb-6eac7521ed9c)


## **Part 3: Simulating Brute Force Attacks & Log Inspection**

### **Step 1: Generate Failed Login Attempts**

1.  Attempt to log in **incorrectly 3 times** using the username `"employee"`.
2.  Log in successfully on the **4th attempt**.

![Screenshot 2025-02-18 180454](https://github.com/user-attachments/assets/c17d58b6-0017-4008-a8bf-75482d1556d4)


### **Step 2: Inspect Security Logs in Event Viewer**

1.  Open **Event Viewer (`eventvwr.msc`)**.
2.  Navigate to: **Windows Logs → Security**.
3.  Look for **Event ID: 4625** (Failed Login Attempts).

![Screenshot 2025-02-18 181033](https://github.com/user-attachments/assets/ab99ada9-782f-4231-9b02-7edc589d16ce)


![Screenshot 2025-02-18 180815](https://github.com/user-attachments/assets/488e3910-4439-4b94-a344-d7eebac8a851)


----------

## **Part 4: Log Forwarding to Microsoft Sentinel**

### **Step 1: Create a Log Analytics Workspace (LAW)**

1.  In **Azure Portal**, search for **Log Analytics Workspaces**.
2.  Click **Create New** → Name it **SecurityLogs-LAW**.
3.  Select **Pricing Tier: Pay-as-you-go**.
4.  Click **Create**.

![Screenshot 2025-02-18 181352](https://github.com/user-attachments/assets/09ea721e-ba1c-45b3-abc0-99597965ec9b)


### **Step 2: Deploy Microsoft Sentinel**

1.  Go to **Microsoft Sentinel**.
2.  Click **Create Sentinel Instance → Connect to Log Analytics**.

![Screenshot 2025-02-18 183144](https://github.com/user-attachments/assets/f0a0e38a-87a7-4e9c-8e14-279557d300a8)


### **Step 3: Enable Windows Security Events Forwarding**

1.  Navigate to **Sentinel → Data Connectors**.
2.  Select **Windows Security Events via AMA**.
3.  Configure **Data Collection Rule (DCR)** to forward logs.

![Screenshot 2025-02-18 183705](https://github.com/user-attachments/assets/73461cca-e013-49bf-b3d2-adf2b1b606c5)


### **Step 4: Query Logs Using KQL (Kusto Query Language)**

Run the following query in **Log Analytics Workspace (LAW) or Sentinel**:

kql

Copy

```
SecurityEvent
| where EventId == 4625

```

![Screenshot 2025-02-18 190906](https://github.com/user-attachments/assets/3c30111a-0350-4557-8805-3258167e7715)


----------

## **Part 5: Log Enrichment with GeoIP Data**

### **Step 1: Import GeoIP Database as a Sentinel Watchlist**

1.  Download **`geoip-summarized.csv`** _(This can be found on Josh Madakor's walkthrough video, link at the top)_
2.  In **Sentinel → Watchlists**, create a new watchlist:
    -   **Name/Alias:** `geoip`
    -   **Source Type:** Local File
    -   **Search Key:** `network`

![Screenshot 2025-02-18 193434](https://github.com/user-attachments/assets/2f3853ad-81e3-4beb-b86d-937bfeeac05e)


### **Step 2: Query Logs with GeoIP Enrichment**

Run the following KQL query to match **attacker IPs with location data**:

kql

Copy

```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP address>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents

```
<img width="960" alt="Screenshot 2025-02-18 202345" src="https://github.com/user-attachments/assets/6fccebfc-c071-458b-826c-ad617c2bdcb8" />

![Screenshot 2025-02-18 202731](https://github.com/user-attachments/assets/89edf671-44b5-4e84-babb-4e2801e5fc8d)

----------

## **Part 6: Attack Map Creation in Microsoft Sentinel**

### **Step 1: Create a New Sentinel Workbook**

1.  Navigate to **Sentinel → Workbooks → Create New**.
2.  Delete pre-populated elements.
3.  Click **Add Query Element**.

![Screenshot 2025-02-19 020455](https://github.com/user-attachments/assets/e5deeb3c-aefe-44f1-ae52-c653079f3651)

![Screenshot 2025-02-19 020334](https://github.com/user-attachments/assets/e887f5bc-0fec-406b-b8fb-d93ea508c7f3)


### **Step 2: Import JSON for Attack Map**

1.  Open **Advanced Editor**.
2.  Paste the JSON from **`map.json`** _(provided separately)_.
3.  Save & observe the real-time attack visualization.

![Screenshot 2025-02-19 021026](https://github.com/user-attachments/assets/f9933c49-c77c-4c2d-b326-7944f1d50364)


----------

## **Conclusion & Next Steps**

### **Key Takeaways**

-   Successfully set up an **Azure Honeypot**.
-   Configured **log forwarding** to **Microsoft Sentinel**.
-   Used **KQL queries** to analyze security events & attacker origins.
-   Enriched logs with **GeoIP data** for geographic insights.
-   Created a **real-time attack map** in **Sentinel**.

 **Further Learning:**

-   **Cyber Range:** Hands-on security training → [Join Here](https://skool.com/cyber-range) _(If you have the money, it's worth it!)_
-   **KC7 Cybersecurity Game (Free):** [Play Here](https://kc7cyber.com/)
-   **Learn KQL:** [KQL Overview](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

 **Next Steps:**

-   Explore **advanced threat-hunting techniques**.
-   Automate **alerts and incident response** workflows.
-   Dive deeper into **KQL and SIEM operations**.
