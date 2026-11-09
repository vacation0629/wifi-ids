import json
import re
import sys
from features import LURE_KEYWORDS, extract_tokens

# Whitelist targets
WHITELIST = [
    "University Campus 5G",
    "University Staff Secure",
    "University Student WiFi",
    "University Guest Portal",
    "eduroam",
    "Siam Wifi",
    "SiamXP Wifi",
    "SIAM WIFI",
    "SIAM XP WIFI"
]

DELIMITERS_REGEX = re.compile(r"[-_\.\s]+")

# Category 1: zero_overlap_semantic_evil_twin (70 samples)
# Ground truth: EVIL_TWIN
cat1_items = [
    {
        "observed_ssid": "Complimentary Patron Broadband",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Deceptive visitor captive portal lure exploiting zero-day terms 'Complimentary', 'Patron', and 'Broadband'.",
        "id": 1
    },
    {
        "observed_ssid": "Unmetered Colloquium Wireless",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Event-based captive trap impersonating guest wireless for symposium and colloquium attendees.",
        "id": 2
    },
    {
        "observed_ssid": "Auditorium Delegate Net",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Public venue lure targeting assembly delegates with zero character overlap against University Guest Portal.",
        "id": 3
    },
    {
        "observed_ssid": "Symposium Attendee AirLink",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Academic gathering rogue access point harvesting credentials from symposium attendees.",
        "id": 4
    },
    {
        "observed_ssid": "Hospitality Suite WLAN",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Hospitality-themed rogue gateway positioned near executive dining and campus visiting lounges.",
        "id": 5
    },
    {
        "observed_ssid": "Conference Participant Hotspot",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Zero-overlap rogue AP targeting registered academic conference attendees without using standard 'guest' lure.",
        "id": 6
    },
    {
        "observed_ssid": "Invited Lecturer Network",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Targeted social engineering hotspot pretending to be reserved connectivity for keynote academic speakers.",
        "id": 7
    },
    {
        "observed_ssid": "Exhibition Hall AccessPoint",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Deceptive campus expo network attracting visiting recruiters and scientific trade fair attendees.",
        "id": 8
    },
    {
        "observed_ssid": "Patron Digital Lounge",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "Hospitality lure mimicking benefactor and library patron lounge infrastructure.",
        "id": 9
    },
    {
        "observed_ssid": "Civic Audience Broadband",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "complimentary_patron_broadband",
        "description": "External visitor trap deployed during public commencement and civic lectures on university grounds.",
        "id": 10
    },
    {
        "observed_ssid": "Campus Registration Desk",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Onboarding captive phishing trap mimicking central campus registration desk to steal institutional identities.",
        "id": 11
    },
    {
        "observed_ssid": "Enrollment Clearance Gateway",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Semester onboarding phishing trap enticing new scholars to submit matriculation credentials.",
        "id": 12
    },
    {
        "observed_ssid": "Identity Validation Kiosk",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Deceptive authentication kiosk pretending to validate visitor credentials while evading standard lure lists.",
        "id": 13
    },
    {
        "observed_ssid": "Orientation CheckIn Counter",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Orientation week rogue trap targeting incoming students during university welcome week.",
        "id": 14
    },
    {
        "observed_ssid": "Matriculation Processing Hub",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Registrar-themed evil twin spoofing official administrative processing channels.",
        "id": 15
    },
    {
        "observed_ssid": "Credentials Issuance Desk",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "IT helpdesk impersonation trap harvesting multi-factor tokens and master staff passwords.",
        "id": 16
    },
    {
        "observed_ssid": "Access Permit Terminal",
        "target_authorized_ssid": "University Guest Portal",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Facility access control spoof prompting guests to enter identity passes.",
        "id": 17
    },
    {
        "observed_ssid": "Account Activation Station",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "New semester account provisioning trap designed to intercept student login strings.",
        "id": 18
    },
    {
        "observed_ssid": "Student Intake Gateway",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Admissions center phishing network simulating mandatory wireless setup for freshmen.",
        "id": 19
    },
    {
        "observed_ssid": "Digital ID Provisioning Hub",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "administrative_onboarding_checkpoint",
        "description": "Smart-card and digital campus badge enrollment lure exploiting zero-overlap administrative phrasing.",
        "id": 20
    },
    {
        "observed_ssid": "Dormitory Instructional Net",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Residential student trap mimicking academic subnet using 'Instructional' and 'Dormitory'.",
        "id": 21
    },
    {
        "observed_ssid": "Undergraduate Curriculum WLAN",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Undergraduate curriculum clone deceiving students into connecting for course materials.",
        "id": 22
    },
    {
        "observed_ssid": "Academic Coursework AirLink",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Classroom wireless lure masquerading as the primary course delivery wireless pipeline.",
        "id": 23
    },
    {
        "observed_ssid": "Collegiate Scholar Network",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Honors student social engineering AP capturing credentials of scholarship recipients.",
        "id": 24
    },
    {
        "observed_ssid": "Syllabus Distribution Broadband",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Lecture hall rogue AP promising direct access to lecture notes and digital syllabus files.",
        "id": 25
    },
    {
        "observed_ssid": "Classroom Lecture Stream",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Auditorium streaming clone intercepting multimedia seminar traffic from student laptops.",
        "id": 26
    },
    {
        "observed_ssid": "Residential Hall Instructional Net",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Housing quad evil twin impersonating institutional dorm-wide study broadband.",
        "id": 27
    },
    {
        "observed_ssid": "Student Commons AirFlow",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Dining hall and recreation center rogue AP capturing transient student devices.",
        "id": 28
    },
    {
        "observed_ssid": "Freshman Quad WLAN",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "First-year dormitory precinct trap harvesting newly issued campus network credentials.",
        "id": 29
    },
    {
        "observed_ssid": "Honors College Broadband",
        "target_authorized_ssid": "University Student WiFi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "academic_instructional_infrastructure",
        "description": "Prestige-themed academic lure baiting high-achieving undergraduate students.",
        "id": 30
    },
    {
        "observed_ssid": "Institutional Faculty WLAN",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Academic synonym clone imitating faculty network using 'Institutional' and 'WLAN'.",
        "id": 31
    },
    {
        "observed_ssid": "Academic Senate Network",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Governance-level spoof aimed at eavesdropping on faculty committee voting and deliberations.",
        "id": 32
    },
    {
        "observed_ssid": "Tenured Personnel AirLink",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Exclusive staff spoof designed to trick senior professors and academic department chairs.",
        "id": 33
    },
    {
        "observed_ssid": "Provost Council Broadband",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Executive administration pretext enticing senior university leadership to connect.",
        "id": 34
    },
    {
        "observed_ssid": "Dean Administrative WLAN",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Collegiate dean office lure designed to capture confidential budgetary correspondence.",
        "id": 35
    },
    {
        "observed_ssid": "Departmental Chair Net",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Targeted department leadership clone placed near faculty meeting chambers.",
        "id": 36
    },
    {
        "observed_ssid": "Faculty Club AccessPoint",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Faculty clubhouse rogue AP intercepting personal and academic device traffic.",
        "id": 37
    },
    {
        "observed_ssid": "Institutional Review Board Net",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Ethics compliance trap targeting medical and psychological human subject researchers.",
        "id": 38
    },
    {
        "observed_ssid": "Chancellor Cabinet Wireless",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Executive suite evil twin broadcasting in main administration building corridors.",
        "id": 39
    },
    {
        "observed_ssid": "Academic Affairs Broadband",
        "target_authorized_ssid": "University Staff Secure",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "institutional_faculty_governance",
        "description": "Curriculum management rogue network soliciting staff single sign-on credentials.",
        "id": 40
    },
    {
        "observed_ssid": "HighBandwidth Express Access",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Speed lure exploiting zero-day terms 'HighBandwidth' and 'Express' with zero token overlap.",
        "id": 41
    },
    {
        "observed_ssid": "Gigabit Fiber AirLink",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Throughput-boosting honeypot promising gigabit transmission rates across campus grounds.",
        "id": 42
    },
    {
        "observed_ssid": "LowLatency Campus Backbone",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Infrastructure spoof attracting research computing and gaming students seeking low ping.",
        "id": 43
    },
    {
        "observed_ssid": "Priority Fiber Hotspot",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Priority bandwidth clone tricking data-intensive users into connecting to a rogue AP.",
        "id": 44
    },
    {
        "observed_ssid": "UltraStream Data Tier",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "High-definition video streaming pretext deployed near student library study zones.",
        "id": 45
    },
    {
        "observed_ssid": "Broadband Expressway Net",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Campus outdoor common area trap promising accelerated web browsing without throttle.",
        "id": 46
    },
    {
        "observed_ssid": "FiberOptic Terminal Access",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Telecommunications hub spoof targeting engineering and physical science students.",
        "id": 47
    },
    {
        "observed_ssid": "Turbo Transmission WLAN",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Radio optimization pretext baiting mobile devices away from University Campus 5G.",
        "id": 48
    },
    {
        "observed_ssid": "DirectLink Gigabit Feed",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Direct optical link impersonation promising unconstrained download bandwidth.",
        "id": 49
    },
    {
        "observed_ssid": "Dynamic Throughput Net",
        "target_authorized_ssid": "University Campus 5G",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "bandwidth_express_prioritization",
        "description": "Quality-of-service pretext masquerading as university load-balanced radio infrastructure.",
        "id": 50
    },
    {
        "observed_ssid": "Siam Chancellor Secretariat Link",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_executive_pretext",
        "description": "Executive lure targeting Siam University leadership without keyword overlap.",
        "id": 51
    },
    {
        "observed_ssid": "Siam Alumni Board Network",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_executive_pretext",
        "description": "Deceptive institutional board network targeting Siam alumni benefactors.",
        "id": 52
    },
    {
        "observed_ssid": "Siam Executive Briefing Net",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_executive_pretext",
        "description": "Administrative lure mimicking Siam executive briefing conference room.",
        "id": 53
    },
    {
        "observed_ssid": "Siam Patron Digital Access",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_executive_pretext",
        "description": "Patron access trap simulating Siam University library foundation connectivity.",
        "id": 54
    },
    {
        "observed_ssid": "Siam Academic Senate WLAN",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "Targeted faculty council rogue access point capturing SiamXP credentials.",
        "id": 55
    },
    {
        "observed_ssid": "Siam Research Fellow AirLink",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "Specialized researcher network lure spoofing SiamXP high-throughput connectivity.",
        "id": 56
    },
    {
        "observed_ssid": "Siam Keynote Speaker Link",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "Symposium keynote speaker trap positioned near Siam auditorium hall.",
        "id": 57
    },
    {
        "observed_ssid": "Siam Symposium Delegate Net",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "Scholarly assembly rogue gateway harvesting delegate logins at Siam University.",
        "id": 58
    },
    {
        "observed_ssid": "Siam Hospitality Lounge Access",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "VIP hospitality pavilion lure operating on Siam University premises.",
        "id": 59
    },
    {
        "observed_ssid": "Siam Convention Broadband",
        "target_authorized_ssid": "Siam Wifi",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "siam_academic_pretext",
        "description": "Event-based unmetered access lure for Siam academic conference attendees.",
        "id": 60
    },
    {
        "observed_ssid": "Global Academic Federation WLAN",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Federated educational consortium clone targeting international visiting researchers.",
        "id": 61
    },
    {
        "observed_ssid": "InterUniversity Roaming Mesh",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Inter-institutional roaming honeypot capturing cross-campus RADIUS authentication packets.",
        "id": 62
    },
    {
        "observed_ssid": "HigherEd Consortium Broadband",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Academic consortium hotspot spoofing reciprocal wireless agreements between universities.",
        "id": 63
    },
    {
        "observed_ssid": "National Research Exchange Net",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "National scientific grid network impersonation aimed at visiting laboratory fellows.",
        "id": 64
    },
    {
        "observed_ssid": "TransNational Scholar Mesh",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "International student and scholar exchange lure harvesting foreign university identities.",
        "id": 65
    },
    {
        "observed_ssid": "Scholarly Exchange Roaming",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Visiting scholar reciprocity network capturing federated 802.1X handshake tokens.",
        "id": 66
    },
    {
        "observed_ssid": "Allied Universities Wireless",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Regional university alliance rogue AP intercepting cross-institutional credentials.",
        "id": 67
    },
    {
        "observed_ssid": "Academic Roaming Alliance",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Zero-overlap eduroam substitute pretending to provide worldwide academic reciprocity.",
        "id": 68
    },
    {
        "observed_ssid": "Global Collegiate Passage",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Study-abroad orientation honeypot gathering credentials from international scholars.",
        "id": 69
    },
    {
        "observed_ssid": "InterCampus Transit WLAN",
        "target_authorized_ssid": "eduroam",
        "category": "zero_overlap_semantic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "federated_roaming_consortium",
        "description": "Multi-campus bus shuttle and transit terminal evil twin intercepting traveling students.",
        "id": 70
    }
]

print(f"Cat1 items loaded: {len(cat1_items)}")

# Category 2: departmental_sister_benign (60 samples)
# Ground truth: BENIGN
cat2_items = [
    {
        "observed_ssid": "Law School Faculty",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authentic enterprise 802.1X wireless network serving faculty in the College of Law.",
        "id": 71
    },
    {
        "observed_ssid": "Medical Center Staff",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Legitimate clinical staff network for university teaching hospital physicians and nurses.",
        "id": 72
    },
    {
        "observed_ssid": "College of Architecture",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authentic design studio wireless infrastructure managed by Architecture IT services.",
        "id": 73
    },
    {
        "observed_ssid": "School of Public Health",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Legitimate epidemiology and community health faculty departmental wireless subnet.",
        "id": 74
    },
    {
        "observed_ssid": "School of Management MBA",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authorized graduate business school student network for MBA seminar amphitheaters.",
        "id": 75
    },
    {
        "observed_ssid": "Faculty of Fine Arts",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Official campus network for visual art studios, sculpture halls, and design faculty.",
        "id": 76
    },
    {
        "observed_ssid": "College of Engineering Net",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authentic high-throughput engineering building WLAN supporting CAD/CAM labs.",
        "id": 77
    },
    {
        "observed_ssid": "Department of Economics",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Legitimate departmental Wi-Fi for faculty economic modeling and statistical seminars.",
        "id": 78
    },
    {
        "observed_ssid": "School of Journalism Media",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authorized student broadcasting and digital multimedia production network.",
        "id": 79
    },
    {
        "observed_ssid": "Faculty of Pharmacy WLAN",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authentic pharmaceutical sciences faculty network with restricted internal subnet access.",
        "id": 80
    },
    {
        "observed_ssid": "College of Education Staff",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Legitimate institutional network for teacher training and pedagogy faculty offices.",
        "id": 81
    },
    {
        "observed_ssid": "School of Music Rehearsal",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authorized conservatory wireless network deployed in orchestral and vocal rehearsal rooms.",
        "id": 82
    },
    {
        "observed_ssid": "Division of Humanities",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Official faculty wireless service for philosophy, history, and literature academic departments.",
        "id": 83
    },
    {
        "observed_ssid": "Graduate School Faculty",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Authorized central administration network for post-graduate degree evaluation committees.",
        "id": 84
    },
    {
        "observed_ssid": "School of Social Work",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "departmental_academic_unit",
        "description": "Legitimate departmental staff and field liaison network in the social welfare institute.",
        "id": 85
    },
    {
        "observed_ssid": "Computer Science Lab 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Authentic computer science robotics and machine learning research laboratory network.",
        "id": 86
    },
    {
        "observed_ssid": "Robotics Institute WLAN",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Legitimate autonomous systems testbed network supporting mobile robot telemetry.",
        "id": 87
    },
    {
        "observed_ssid": "Biomedical Research Cluster",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Authentic high-performance biomedical computing cluster network for genomic researchers.",
        "id": 88
    },
    {
        "observed_ssid": "Physics Nanotechnology Lab",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Cleanroom research laboratory network for nanolithography and condensed matter physics.",
        "id": 89
    },
    {
        "observed_ssid": "Observatory Telescope Array",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Authorized astrophysics observatory network linking optical telescope control systems.",
        "id": 90
    },
    {
        "observed_ssid": "Aerospace Wind Tunnel Lab",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Experimental aerodynamics test facility network operating within engineering complex.",
        "id": 91
    },
    {
        "observed_ssid": "Genomics Sequencing Center",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "High-throughput DNA sequencing facility network transmitting large bioinformatics datasets.",
        "id": 92
    },
    {
        "observed_ssid": "Quantum Computing Facility",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Cryogenic quantum information research laboratory network for post-doctoral scientists.",
        "id": 93
    },
    {
        "observed_ssid": "Marine Biology Station Net",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Off-main-campus coastal research station network connected via institutional site VPN.",
        "id": 94
    },
    {
        "observed_ssid": "Materials Science Foundry",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Advanced metallurgy and crystallography clean lab wireless instrument network.",
        "id": 95
    },
    {
        "observed_ssid": "Neuroscience Imaging Center",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Authentic functional MRI and brain mapping research center diagnostic wireless.",
        "id": 96
    },
    {
        "observed_ssid": "Supercomputing Center Internal",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Administrative wireless VLAN inside the central university datacenter and HPC cluster.",
        "id": 97
    },
    {
        "observed_ssid": "Renewable Energy Testbed",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Solar microgrid and wind turbine experimental array research network.",
        "id": 98
    },
    {
        "observed_ssid": "Data Science Institute WLAN",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "University-wide interdisciplinary data science faculty and graduate research hub.",
        "id": 99
    },
    {
        "observed_ssid": "Chemical Synthesis Lab",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "specialized_research_facility",
        "description": "Fume hood and spectroscopy sensor network inside organic chemistry research suites.",
        "id": 100
    },
    {
        "observed_ssid": "Central Library Commons",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Authentic public quiet study zone network operated by main university library.",
        "id": 101
    },
    {
        "observed_ssid": "Science Library Periodicals",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Legitimate branch library study hall wireless serving science and mathematics majors.",
        "id": 102
    },
    {
        "observed_ssid": "Rare Books Manuscript Archive",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Secured archival reading room network restricted to registered historical researchers.",
        "id": 103
    },
    {
        "observed_ssid": "Digital Media Commons WiFi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Official campus library media lab supporting 3D printing and audio-visual editing.",
        "id": 104
    },
    {
        "observed_ssid": "Law Library Reference Desk",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Authentic reference desk network inside the law school legal research collection.",
        "id": 105
    },
    {
        "observed_ssid": "Medical Library Study Hub",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Legitimate quiet reading room wireless network inside health sciences library.",
        "id": 106
    },
    {
        "observed_ssid": "Art Museum Gallery WLAN",
        "target_authorized_ssid": "University Guest Portal",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "University art museum visitor guide and interactive exhibit wireless system.",
        "id": 107
    },
    {
        "observed_ssid": "Herbarium Botanical Archive",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Authorized plant taxonomy research and herbarium cataloging staff network.",
        "id": 108
    },
    {
        "observed_ssid": "Music Library Listening Room",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Audiophile listening terminal and sheet music digital repository wireless network.",
        "id": 109
    },
    {
        "observed_ssid": "Undergraduate Library Commons",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "library_archives_facility",
        "description": "Authentic undergraduate collaborative study center open 24/7 during final exam cycles.",
        "id": 110
    },
    {
        "observed_ssid": "Student Union Recreation",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Authentic student union building lounge, gaming, and student club wireless network.",
        "id": 111
    },
    {
        "observed_ssid": "Alumni Memorial Lounge",
        "target_authorized_ssid": "University Guest Portal",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Legitimate hospitality network in campus alumni center for visiting graduates.",
        "id": 112
    },
    {
        "observed_ssid": "Graduate Student Center",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Official graduate student council commons and doctoral study wing network.",
        "id": 113
    },
    {
        "observed_ssid": "Athletics Arena Facilities",
        "target_authorized_ssid": "University Campus 5G",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Authorized university sports stadium and basketball arena operational wireless.",
        "id": 114
    },
    {
        "observed_ssid": "Campus Recreation Center Net",
        "target_authorized_ssid": "University Student WiFi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Legitimate intramural gymnasium and fitness facility wireless service.",
        "id": 115
    },
    {
        "observed_ssid": "International House Lounge",
        "target_authorized_ssid": "University Guest Portal",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Authentic cultural center and international student residence lounge wireless.",
        "id": 116
    },
    {
        "observed_ssid": "University Bookstore Guest",
        "target_authorized_ssid": "University Guest Portal",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Authorized customer Wi-Fi inside campus bookstore retail complex.",
        "id": 117
    },
    {
        "observed_ssid": "Performing Arts Center Lobby",
        "target_authorized_ssid": "University Guest Portal",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Official concert hall and university theater patron hospitality network.",
        "id": 118
    },
    {
        "observed_ssid": "Residence Life Staff Office",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Restricted administrative wireless for resident directors and dormitory coordinators.",
        "id": 119
    },
    {
        "observed_ssid": "Student Health Center Clinic",
        "target_authorized_ssid": "University Staff Secure",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "student_union_campus_life",
        "description": "Encrypted clinical EHR network for university student wellness medical staff.",
        "id": 120
    },
    {
        "observed_ssid": "Siam Engineering Faculty",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Legitimate Faculty of Engineering departmental network at Siam University.",
        "id": 121
    },
    {
        "observed_ssid": "Siam Medical Nursing Lab",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Authorized clinical nursing skills lab network at Siam University medical center.",
        "id": 122
    },
    {
        "observed_ssid": "Siam Science Tech Center",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Authorized high-performance science laboratory network on SiamXP infrastructure.",
        "id": 123
    },
    {
        "observed_ssid": "Siam Business Administration",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Legitimate business school student and faculty departmental network.",
        "id": 124
    },
    {
        "observed_ssid": "Siam Law Faculty WLAN",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Official legal clinic and faculty of law research wireless subnet.",
        "id": 125
    },
    {
        "observed_ssid": "Siam Robotics Research Lab",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Advanced robotics laboratory experimental high-throughput access point.",
        "id": 126
    },
    {
        "observed_ssid": "Siam Artificial Intelligence Lab",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Authorized AI research cluster wireless telemetry interface at Siam University.",
        "id": 127
    },
    {
        "observed_ssid": "Siam Pharmacy Department",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Legitimate pharmacy dispensing instructional lab wireless network.",
        "id": 128
    },
    {
        "observed_ssid": "Siam Liberal Arts Division",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Official foreign languages and liberal arts faculty department network.",
        "id": 129
    },
    {
        "observed_ssid": "Siam Communication Arts Studio",
        "target_authorized_ssid": "Siam Wifi",
        "category": "departmental_sister_benign",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "siam_departmental",
        "description": "Broadcasting and multimedia production studio educational network.",
        "id": 130
    }
]

print(f"Cat2 items loaded: {len(cat2_items)}")

# Category 3: classical_orthographic_evil_twin (40 samples)
# Ground truth: EVIL_TWIN
cat3_items = [
    {
        "observed_ssid": "Un1versity Campus 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Visual homoglyph replacing lowercase 'i' with numeral '1' in 'Un1versity'.",
        "id": 131
    },
    {
        "observed_ssid": "University Carnpus 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "visual_kerning_collision",
        "description": "Kerning attack replacing 'm' with 'rn' ('Carnpus') appearing identical in sans-serif fonts.",
        "id": 132
    },
    {
        "observed_ssid": "University Campup 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "character_transposition_typo",
        "description": "Keyboard transposition typo replacing terminal 's' with adjacent key 'p' ('Campup').",
        "id": 133
    },
    {
        "observed_ssid": "Unversity Campus 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "omission_typosquatting",
        "description": "Typosquatting evil twin with single vowel omission ('Unversity' missing 'i').",
        "id": 134
    },
    {
        "observed_ssid": "University-Campus-5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing underscores with hyphens to bypass exact string match.",
        "id": 135
    },
    {
        "observed_ssid": "University Campus 5g",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "casing_mutation",
        "description": "Subtle casing mutation replacing capital '5G' with lowercase '5g'.",
        "id": 136
    },
    {
        "observed_ssid": "Free University Campus 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Social engineering word addition prepending deceptive lure prefix 'Free_'.",
        "id": 137
    },
    {
        "observed_ssid": "University Campus 5G Fast",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Throughput lure appending deceptive speed keyword '_Fast'.",
        "id": 138
    },
    {
        "observed_ssid": "University Campus 5G Official",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Authority lure appending deceptive institutional keyword '_Official'.",
        "id": 139
    },
    {
        "observed_ssid": "University Campu5 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "leetspeak_obfuscation",
        "description": "Leetspeak substitution replacing letter 's' with numeral '5' in 'Campu5'.",
        "id": 140
    },
    {
        "observed_ssid": "University Staff Secur3",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "leetspeak_obfuscation",
        "description": "Leetspeak substitution replacing terminal 'e' with digit '3' ('Secur3').",
        "id": 141
    },
    {
        "observed_ssid": "University Staft Secure",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "omission_typosquatting",
        "description": "Typosquatting mutation replacing 'ff' with 'ft' ('Staft') in employee network.",
        "id": 142
    },
    {
        "observed_ssid": "University-Staff-Secure",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation substituting underscores with hyphens across staff network name.",
        "id": 143
    },
    {
        "observed_ssid": "University Staff Secure Login",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Deceptive captive portal suffix lure '_Login' appended to staff secure SSID.",
        "id": 144
    },
    {
        "observed_ssid": "Official University Staff Secure",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Authority lure prepending 'Official_' to mimic authorized employee 802.1X service.",
        "id": 145
    },
    {
        "observed_ssid": "Un1versity Staff Secure",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Visual homoglyph replacing 'i' with '1' in staff enterprise network SSID.",
        "id": 146
    },
    {
        "observed_ssid": "University Staff Secrue",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "character_transposition_typo",
        "description": "Typographic character transposition swapping 'ur' to 'ru' ('Secrue').",
        "id": 147
    },
    {
        "observed_ssid": "University Staff Secure AutoConnect",
        "target_authorized_ssid": "University Staff Secure",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Convenience lure appending '_AutoConnect' to induce quick user association.",
        "id": 148
    },
    {
        "observed_ssid": "University Studnet WiFi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "character_transposition_typo",
        "description": "Keyboard transposition swapping 'en' to 'ne' ('Studnet') targeting mobile students.",
        "id": 149
    },
    {
        "observed_ssid": "University Student W1F1",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "leetspeak_obfuscation",
        "description": "Leetspeak substitution replacing both 'i' letters with '1' ('W1F1').",
        "id": 150
    },
    {
        "observed_ssid": "Free University Student WiFi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Captive lure prepending 'Free_' to authorized student wireless network name.",
        "id": 151
    },
    {
        "observed_ssid": "University Student WiFi Portal",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Phishing portal lure appending '_Portal' to harvest campus LMS logins.",
        "id": 152
    },
    {
        "observed_ssid": "University-Student-WiFi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing underscores with hyphens in student network.",
        "id": 153
    },
    {
        "observed_ssid": "Un1versity Student WiFi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Visual homoglyph replacing 'i' with '1' in 'Un1versity_Student_WiFi'.",
        "id": 154
    },
    {
        "observed_ssid": "University Student WiFi VIP",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Privilege escalation lure appending '_VIP' promising faster streaming access.",
        "id": 155
    },
    {
        "observed_ssid": "University Student Wifi",
        "target_authorized_ssid": "University Student WiFi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "casing_mutation",
        "description": "Casing mutation replacing uppercase 'WiFi' with sentence-cased 'Wifi'.",
        "id": 156
    },
    {
        "observed_ssid": "University Guest P0rtal",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Homoglyph substitution replacing letter 'o' with digit '0' ('P0rtal').",
        "id": 157
    },
    {
        "observed_ssid": "University Guest Porta1",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Homoglyph substitution replacing lowercase 'l' with numeral '1' ('Porta1').",
        "id": 158
    },
    {
        "observed_ssid": "University Geust Portal",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "character_transposition_typo",
        "description": "Transposition typo swapping adjacent letters 'ue' to 'eu' ('Geust').",
        "id": 159
    },
    {
        "observed_ssid": "Free University Guest Portal",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Pretext lure prepending 'Free_' to official campus guest portal name.",
        "id": 160
    },
    {
        "observed_ssid": "University-Guest-Portal",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing underscores with hyphens in visitor network.",
        "id": 161
    },
    {
        "observed_ssid": "University Guest Portal Verify",
        "target_authorized_ssid": "University Guest Portal",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Credential harvesting captive trap appending security keyword '_Verify'.",
        "id": 162
    },
    {
        "observed_ssid": "Siam_Wifi",
        "target_authorized_ssid": "Siam Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing space with underscore targeting Siam Wifi.",
        "id": 163
    },
    {
        "observed_ssid": "Siam-Wifi",
        "target_authorized_ssid": "Siam Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing space with hyphen targeting Siam Wifi.",
        "id": 164
    },
    {
        "observed_ssid": "Siam.Wifi",
        "target_authorized_ssid": "Siam Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing space with period targeting Siam Wifi.",
        "id": 165
    },
    {
        "observed_ssid": "Siam W1f1",
        "target_authorized_ssid": "Siam Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Visual homoglyph replacing 'i' with digit '1' in 'W1f1' targeting Siam Wifi.",
        "id": 166
    },
    {
        "observed_ssid": "Free Siam Wifi",
        "target_authorized_ssid": "Siam Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "lure_word_injection",
        "description": "Deceptive free access lure prepending 'Free' targeting Siam Wifi.",
        "id": 167
    },
    {
        "observed_ssid": "SiamXP_Wifi",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing space with underscore targeting SiamXP Wifi.",
        "id": 168
    },
    {
        "observed_ssid": "SiamXP-Wifi",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "delimiter_mutation",
        "description": "Delimiter mutation replacing space with hyphen targeting SiamXP Wifi.",
        "id": 169
    },
    {
        "observed_ssid": "SiamXP W1f1",
        "target_authorized_ssid": "SiamXP Wifi",
        "category": "classical_orthographic_evil_twin",
        "ground_truth_label": "EVIL_TWIN",
        "semantic_pretext_type": "homoglyph_substitution",
        "description": "Visual homoglyph replacing 'i' with digit '1' targeting SiamXP Wifi.",
        "id": 170
    }
]

print(f"Cat3 items loaded: {len(cat3_items)}")

# Category 4: ambient_environmental_noise (40 samples)
# Ground truth: BENIGN
cat4_items = [
    {
        "observed_ssid": "Starbucks WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Legitimate commercial coffee shop Wi-Fi network located adjacent to campus perimeter.",
        "id": 171
    },
    {
        "observed_ssid": "Cafe Amazon",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Commercial cafe wireless network operating in retail plaza bordering campus.",
        "id": 172
    },
    {
        "observed_ssid": "Costa Coffee Guest",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Retail coffee chain customer wireless network near university avenue.",
        "id": 173
    },
    {
        "observed_ssid": "Dunkin Donuts Guest",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Commercial franchise customer guest network across from student dormitory.",
        "id": 174
    },
    {
        "observed_ssid": "Subway Free WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Fast food restaurant public wireless hotspot located on university perimeter.",
        "id": 175
    },
    {
        "observed_ssid": "McDonalds Free WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Commercial fast-food customer network with standard vendor captive portal.",
        "id": 176
    },
    {
        "observed_ssid": "Blue Bottle Coffee",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Specialty cafe Wi-Fi network patronized by students and off-campus faculty.",
        "id": 177
    },
    {
        "observed_ssid": "Chipotle Guest",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Retail dining customer wireless network in campus center commercial strip.",
        "id": 178
    },
    {
        "observed_ssid": "Peets Coffee WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Commercial retail coffee roaster wireless access point near university bookstore.",
        "id": 179
    },
    {
        "observed_ssid": "Panera Bread WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Bakery cafe public customer network commonly used by studying undergraduates.",
        "id": 180
    },
    {
        "observed_ssid": "AIS SUPER WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Commercial cellular carrier high-density carrier Wi-Fi offload access point.",
        "id": 181
    },
    {
        "observed_ssid": "TrueMove 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "National mobile telecommunications provider public wireless hotspot.",
        "id": 182
    },
    {
        "observed_ssid": "dtac WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Commercial mobile network operator public subscriber Wi-Fi service.",
        "id": 183
    },
    {
        "observed_ssid": "Xfinity WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Commercial broadband provider outdoor subscriber hotspot beaconing near campus.",
        "id": 184
    },
    {
        "observed_ssid": "ATT WiFi Public",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Telecommunications company managed municipal public hotspot.",
        "id": 185
    },
    {
        "observed_ssid": "Verizon 5G Hotspot",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Cellular carrier fixed wireless access gateway on university boundary.",
        "id": 186
    },
    {
        "observed_ssid": "T-Mobile Highway",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Mobile network operator macro-cell outdoor carrier offload network.",
        "id": 187
    },
    {
        "observed_ssid": "Google Fiber Guest",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Commercial fiber optic internet customer access point in nearby residential zone.",
        "id": 188
    },
    {
        "observed_ssid": "Spectrum Mobile",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Commercial cable operator community Wi-Fi access point near campus border.",
        "id": 189
    },
    {
        "observed_ssid": "City Municipal FreeNet",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "cellular_carrier_telecom",
        "description": "Municipal city government public internet service available in adjacent public park.",
        "id": 190
    },
    {
        "observed_ssid": "Metro Transit Free",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "public_municipal_transit",
        "description": "Metropolitan light rail authority commuter wireless at university station.",
        "id": 191
    },
    {
        "observed_ssid": "City Bus Passenger WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "public_municipal_transit",
        "description": "Municipal transit bus passenger Wi-Fi passing through university avenue.",
        "id": 192
    },
    {
        "observed_ssid": "Subway Station Platform",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "public_municipal_transit",
        "description": "Underground subway transit passenger Wi-Fi detected from ground-level campus sensor.",
        "id": 193
    },
    {
        "observed_ssid": "LightRail Commuter Net",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "public_municipal_transit",
        "description": "Commuter train station Wi-Fi detected along western border of campus.",
        "id": 194
    },
    {
        "observed_ssid": "Airport Express Lounge",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "public_municipal_transit",
        "description": "Regional transit airport shuttle departure lounge passenger wireless network.",
        "id": 195
    },
    {
        "observed_ssid": "John iPhone14",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "personal_mobile_hotspot",
        "description": "Ephemeral iOS personal smartphone tethering hotspot carried by a pedestrian.",
        "id": 196
    },
    {
        "observed_ssid": "Sarah Galaxy S23",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "personal_mobile_hotspot",
        "description": "Transient Android smartphone mobile hotspot broadcasting temporary tethering signal.",
        "id": 197
    },
    {
        "observed_ssid": "Alex Pixel Pro",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "personal_mobile_hotspot",
        "description": "Personal portable hotspot operated from Google Pixel smartphone near campus quad.",
        "id": 198
    },
    {
        "observed_ssid": "David MacBook Air",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "personal_mobile_hotspot",
        "description": "Ad-hoc peer-to-peer Wi-Fi network created by a student laptop for local file transfer.",
        "id": 199
    },
    {
        "observed_ssid": "AndroidAP 9823",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "personal_mobile_hotspot",
        "description": "Default OEM smartphone tethering SSID with pseudo-random hardware numeric suffix.",
        "id": 200
    },
    {
        "observed_ssid": "Residence Hall 304",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "off_campus_residential_retail",
        "description": "Private residential apartment Wi-Fi router broadcasting from across university street.",
        "id": 201
    },
    {
        "observed_ssid": "Campus Edge Apartments",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "off_campus_residential_retail",
        "description": "Private commercial student housing apartment complex residential Wi-Fi network.",
        "id": 202
    },
    {
        "observed_ssid": "University Square Condos",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "off_campus_residential_retail",
        "description": "Privately owned off-campus residential condominium association wireless network.",
        "id": 203
    },
    {
        "observed_ssid": "College Park Suites 4G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "off_campus_residential_retail",
        "description": "Private student apartment leasing complex residential network near campus south gate.",
        "id": 204
    },
    {
        "observed_ssid": "Siam Commercial Bank WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_banking_retail",
        "description": "Commercial branch banking customer Wi-Fi operating near university grounds.",
        "id": 205
    },
    {
        "observed_ssid": "Bangkok Transit System WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "municipal_transit",
        "description": "Metropolitan mass transit public passenger Wi-Fi at adjacent BTS station.",
        "id": 206
    },
    {
        "observed_ssid": "Cafe Amazon Phasi Charoen",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "commercial_coffee_retail",
        "description": "Commercial coffee franchise customer Wi-Fi located near Siam University entrance.",
        "id": 207
    },
    {
        "observed_ssid": "7Eleven Siam Campus Branch",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "convenience_retail",
        "description": "Convenience retail chain store public access point outside university gate.",
        "id": 208
    },
    {
        "observed_ssid": "TrueMove H Public 5G",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "telecom_carrier_offload",
        "description": "Commercial cellular telecommunications provider public offload hotspot.",
        "id": 209
    },
    {
        "observed_ssid": "AIS SMART Life WiFi",
        "target_authorized_ssid": "University Campus 5G",
        "category": "ambient_environmental_noise",
        "ground_truth_label": "BENIGN",
        "semantic_pretext_type": "telecom_carrier_offload",
        "description": "National carrier public customer access point operating in perimeter shopping area.",
        "id": 210
    }
]

print(f"Cat4 items loaded: {len(cat4_items)}")

all_samples = []
for idx, s in enumerate(cat1_items + cat2_items + cat3_items + cat4_items, start=1):
    s_copy = dict(s)
    s_copy["id"] = idx
    all_samples.append(s_copy)

print(f"Total samples combined: {len(all_samples)}")

from collections import Counter
print("Counts per category:", Counter(s["category"] for s in all_samples))
print("Counts per label:", Counter(s["ground_truth_label"] for s in all_samples))

# Validation
observed_ssids = [s["observed_ssid"] for s in all_samples]
if len(observed_ssids) != len(set(observed_ssids)):
    print("ERROR: Duplicates found!")
    sys.exit(1)
else:
    print("All observed SSIDs are 100% unique!")

cat1_violations = []
for s in cat1_items:
    tokens = extract_tokens(s["observed_ssid"])
    for t in tokens:
        if t in LURE_KEYWORDS:
            cat1_violations.append((s["observed_ssid"], t))

if cat1_violations:
    print("ERROR: Lure keyword violations in Category 1:", cat1_violations)
    sys.exit(1)
else:
    print("Category 1 is 100% free of the 19 naive lure keywords!")

out_path = r"D:\Antigravity Project\Rogue wifi\ssid_feature_framework\extended_200_test_cases.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(all_samples, f, indent=2, ensure_ascii=False)

print(f"Successfully generated and verified dataset at: {out_path}")
