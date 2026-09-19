"""Convert red_agent_plan.md to PDF using reportlab."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import Flowable
import re

PAGE_W, PAGE_H = A4

# ─── Custom Styles ────────────────────────────────────────────────────────────

styles = getSampleStyleSheet()

styles.add(ParagraphStyle(
    name='DocTitle',
    fontSize=24,
    fontName='Helvetica-Bold',
    textColor=colors.HexColor('#1a1a2e'),
    spaceAfter=6,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name='DocSubtitle',
    fontSize=13,
    fontName='Helvetica',
    textColor=colors.HexColor('#4a4a6a'),
    spaceAfter=4,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name='DocMeta',
    fontSize=10,
    fontName='Helvetica-Oblique',
    textColor=colors.HexColor('#888888'),
    spaceAfter=20,
    alignment=TA_CENTER,
))
styles.add(ParagraphStyle(
    name='H1',
    fontSize=16,
    fontName='Helvetica-Bold',
    textColor=colors.HexColor('#1a1a2e'),
    spaceBefore=18,
    spaceAfter=8,
    borderPad=0,
))
styles.add(ParagraphStyle(
    name='H2',
    fontSize=13,
    fontName='Helvetica-Bold',
    textColor=colors.HexColor('#2d4a8a'),
    spaceBefore=14,
    spaceAfter=6,
))
styles.add(ParagraphStyle(
    name='H3',
    fontSize=11,
    fontName='Helvetica-Bold',
    textColor=colors.HexColor('#3a3a5a'),
    spaceBefore=10,
    spaceAfter=4,
))
styles.add(ParagraphStyle(
    name='BodyPara',
    fontSize=10,
    fontName='Helvetica',
    textColor=colors.HexColor('#222222'),
    leading=16,
    spaceAfter=8,
    alignment=TA_JUSTIFY,
))
styles.add(ParagraphStyle(
    name='BulletItem',
    fontSize=10,
    fontName='Helvetica',
    textColor=colors.HexColor('#222222'),
    leading=15,
    spaceAfter=4,
    leftIndent=16,
    bulletIndent=4,
))
styles.add(ParagraphStyle(
    name='CodeBlockStyle',
    fontSize=8.5,
    fontName='Courier',
    textColor=colors.HexColor('#2c2c2c'),
    backgroundColor=colors.HexColor('#f4f4f8'),
    leading=13,
    leftIndent=20,
    rightIndent=20,
    spaceAfter=10,
    spaceBefore=6,
))
styles.add(ParagraphStyle(
    name='QuoteStyle',
    fontSize=10,
    fontName='Helvetica-Oblique',
    textColor=colors.HexColor('#555555'),
    leading=15,
    leftIndent=24,
    rightIndent=24,
    spaceAfter=10,
))
styles.add(ParagraphStyle(
    name='TableCell',
    fontSize=9,
    fontName='Helvetica',
    textColor=colors.HexColor('#222222'),
    leading=13,
))
styles.add(ParagraphStyle(
    name='TableHeader',
    fontSize=9,
    fontName='Helvetica-Bold',
    textColor=colors.HexColor('#ffffff'),
    leading=13,
))
styles.add(ParagraphStyle(
    name='TableCellMono',
    fontSize=8.5,
    fontName='Courier',
    textColor=colors.HexColor('#2c2c2c'),
    leading=12,
))
styles.add(ParagraphStyle(
    name='BulletMono',
    fontSize=8.5,
    fontName='Courier',
    textColor=colors.HexColor('#2c2c2c'),
    leading=13,
    leftIndent=28,
    spaceAfter=2,
))

# ─── Color constants ───────────────────────────────────────────────────────────
ACCENT    = colors.HexColor('#2d4a8a')
LIGHT_BG  = colors.HexColor('#f0f4ff')
RULE_CLR  = colors.HexColor('#2d4a8a')
DIVIDER   = colors.HexColor('#cccccc')

# ─── Helper: code block as a shaded paragraph ─────────────────────────────────

def code(text):
    """Return a shaded block paragraph that looks like code."""
    return Paragraph(
        f'<font color="#2c2c2c">{text}</font>',
        styles['CodeBlockStyle']
    )

def section_title(text):
    return Paragraph(text, styles['H1'])

def subsection_title(text):
    return Paragraph(text, styles['H2'])

def sub3(text):
    return Paragraph(text, styles['H3'])

def body(text):
    return Paragraph(text, styles['BodyPara'])

def bullet(text):
    return Paragraph(f'<bullet>&bull;</bullet>{text}', styles['BulletItem'])

def quote(text):
    return Paragraph(f'"{text}"', styles['QuoteStyle'])

def sp(n=1):
    return Spacer(1, n * 0.2 * cm)

def rule():
    return HRFlowable(width='100%', thickness=1, color=RULE_CLR, spaceAfter=4, spaceBefore=4)

def title_block():
    items = [
        sp(1),
        Paragraph('Red Agent Plan', styles['DocTitle']),
        Paragraph('Nexus Workspace — Autonomous Security Assessment', styles['DocSubtitle']),
        sp(0.5),
        Paragraph(
            'Date: September 2026 &nbsp;&nbsp;|&nbsp;&nbsp; '
            'Target: Nexus Workspace SaaS Environment &nbsp;&nbsp;|&nbsp;&nbsp; '
            'Method: Formula-Based Discovery',
            styles['DocMeta']
        ),
        HRFlowable(width='100%', thickness=2, color=RULE_CLR, spaceAfter=10),
    ]
    return items

# ─── Build document ───────────────────────────────────────────────────────────

def build_pdf(input_md, output_pdf):
    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=A4,
        leftMargin=2.2*cm,
        rightMargin=2.2*cm,
        topMargin=2.0*cm,
        bottomMargin=2.0*cm,
        title='Red Agent Plan — Nexus Workspace',
        author='Red Agent',
        subject='Autonomous Security Assessment Plan',
    )

    story = []

    # Title
    story += title_block()

    # ── 1. The Red Agent's Job ─��─────────────────────────────────────────────
    story.append(section_title('1. The Red Agent\'s Job'))
    story.append(body(
        '<b>Goal:</b> Starting as a regular user with zero knowledge of the system, reach the '
        '<font color="#2d4a8a">/internal/api-keys</font> endpoint that only a "system" role can access.'
    ))
    story.append(body(
        '<b>Constraint:</b> The agent has no insider knowledge. It does not read config files, '
        'source code, or documentation. It learns entirely through interaction.'
    ))
    story.append(sp())

    # ── 2. How It Thinks ───────────────────────────────────────────────────
    story.append(section_title('2. How It Thinks'))

    story.append(subsection_title('Phase 1 — Map the Territory'))
    story.append(body(
        'The agent starts with no access and registers an account. It now has a token and '
        'a basic user identity. From here, it begins a systematic survey.'
    ))
    story.append(sp())

    # Code block for START
    start_code = (
        'START:\n'
        '  - Register → get token → what does this token allow?\n\n'
        '  For every endpoint it can call:\n'
        '    - What did I send? (request)\n'
        '    - What came back? (response)\n'
        '    - Was this what SHOULD have come back?\n\n'
        '    Unexpected responses are the agent\'s bread and butter:\n'
        '      - 200 when it expected 403 → something is too permissive\n'
        '      - More data returned than expected → information disclosure\n'
        '      - Less data returned → something changed, worth investigating\n'
        '      - Slower response → something is happening behind the scenes\n'
        '      - Error message contains a secret URL or token → straight to findings'
    )
    story.append(code(start_code))

    story.append(body(
        'The agent doesn\'t know what "unexpected" means by label. It measures it mathematically:'
    ))
    story.append(code(
        'Expected response = what a properly secured endpoint returns\n'
        'Actual response   = what the endpoint actually returned\n\n'
        'Δ = actual - expected\n\n'
        'If |Δ| > threshold:\n'
        '    → Flag as anomaly\n'
        '    → Investigate deeper'
    ))
    story.append(sp())

    story.append(subsection_title('Phase 2 — Build the Permission Graph'))
    story.append(body(
        'As the agent explores, it maps the system as a <b>graph of capabilities</b>:'
    ))
    story.append(code(
        'NODE = a permission level (guest, user, admin, system)\n'
        'EDGE = an action that moves the agent between nodes\n\n'
        'The agent\'s job: find a PATH from user → system\n\n'
        'But it doesn\'t know where the edges are yet.\n'
        'It discovers them by trying things.'
    ))
    story.append(body(
        'The graph is built purely from observations:'
    ))

    obs_code = (
        'Observation 1:\n'
        '  Call GET /users/me → I see my own user ID and role\n'
        '  Call GET /users/{other_user_id} → I got their data\n'
        '  Δ = I was NOT supposed to see other users\' data\n'
        '  Edge found: Guest/User can enumerate all users\n\n'
        'Observation 2:\n'
        '  Call POST /api-keys → Got a new API key with my scopes\n'
        '  Call PUT /api-keys/{key_id} → Changed scopes to ["admin"]\n'
        '  Δ = I was NOT supposed to be able to escalate my own scopes\n'
        '  Edge found: User can become admin via API key modification\n\n'
        'Observation 3:\n'
        '  Call POST /integrations/connect → Integration connected\n'
        '  Webhook fires internally → Check webhook logs\n'
        '  Δ = Webhook payload contains tokens that were never visible in the API\n'
        '  Edge found: Integration interaction exposes hidden data'
    )
    story.append(code(obs_code))
    story.append(body(
        'Each observation alone is a data point. The agent chains them.'
    ))
    story.append(sp())

    story.append(subsection_title('Phase 3 — Chain Low-Severity into High-Severity'))
    story.append(body(
        'This is the core of how the agent thinks. It doesn\'t look for one big vulnerability — '
        'it looks for <b>chains of small permissions that combine into a big reach</b>.'
    ))
    story.append(body(
        'The agent chains observations together, using each one as a stepping stone to the next:'
    ))

    chain_code = (
        'Step 1: Start as regular user\n'
        '         → Can view any user profile (IDOR)\n'
        '         → Knows admin\'s user ID\n\n'
        'Step 2: Create an API key\n'
        '         → Key has limited scopes by default\n'
        '         → Can modify own API key scopes (Privilege Escalation)\n'
        '         → Upgrades key to ["admin"]\n\n'
        'Step 3: With admin scopes, call /admin/settings\n'
        '         → Admin settings are exposed to admin role\n'
        '         → Reveals Stripe webhook secret and OAuth credentials\n\n'
        'Step 4: With Stripe webhook secret, forge billing events\n'
        '         → Webhook endpoint accepts events without verifying sender\n'
        '         → Escalate own account to admin via forged event\n\n'
        'Step 5: With admin role, call /admin/audit\n'
        '         → Audit log shows internal API key table structure\n'
        '         → Shows which users have system-level access\n\n'
        'Step 6: With knowledge from audit log + admin access,\n'
        '         call /internal/api-keys\n'
        '         → TARGET REACHED'
    )
    story.append(code(chain_code))
    story.append(body(
        'The agent doesn\'t know these steps in advance. It discovers them one by one, '
        'measuring deviations at each step.'
    ))
    story.append(sp())

    story.append(subsection_title('Phase 4 — The Deviation Formula'))
    story.append(body(
        'For every action the agent takes, it measures:'
    ))

    metric_data = [
        [Paragraph('METRIC', styles['TableHeader']),
         Paragraph('FORMULA', styles['TableHeader'])],
        ['Status Deviation',  'actual_status ≠ expected_status'],
        ['Data Leak',         'actual_response > expected_size'],
        ['Time Anomaly',      'response_time > baseline × 2'],
        ['Scope Leak',        'response reveals hidden tokens'],
        ['Access Bypass',     '403/401 → 200 on retry'],
        ['Data Enumeration',  'sequential IDs return valid data'],
        ['Role Confusion',    'user role acts as admin role'],
    ]

    metric_table = Table(metric_data, colWidths=[5.5*cm, 9.5*cm])
    metric_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0),  ACCENT),
        ('BACKGROUND',  (0, 1), (-1, -1), colors.white),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8f8fc'), colors.white]),
        ('GRID',        (0, 0), (-1, -1), 0.4, DIVIDER),
        ('FONTNAME',    (0, 1), (-1, -1), 'Helvetica'),
        ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',   (0, 0), (-1, 0),  colors.white),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',(0, 0), (-1, -1), 8),
        ('TOPPADDING',  (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(metric_table)
    story.append(sp(0.5))

    story.append(quote(
        'This is outside the normal distribution. Worth investigating.'
    ))
    story.append(sp())

    story.append(subsection_title('Phase 5 — Reaching the Target'))
    story.append(body('The agent knows it\'s reached the target when:'))
    story.append(code(
        'Target condition:\n'
        '  Response from endpoint contains ALL user API keys\n'
        '  AND role in response = "system"\n\n'
        'The agent doesn\'t stop at intermediate wins.\n'
        'It keeps going until it hits the actual crown jewels.'
    ))
    story.append(sp())

    # ── 3. Operational Loop ──────────────────────────────────────────────────
    story.append(section_title('3. The Agent\'s Operational Loop'))
    story.append(body('The agent repeats this loop until the target is reached:'))

    loop_code = (
        'LOOP until target reached:\n\n'
        '  1. PROBE\n'
        '     Send a request to every known endpoint\n'
        '     Measure response against baseline\n\n'
        '  2. CATALOG\n'
        '     Build a list of: what\'s accessible, what\'s not,\n'
        '     what\'s partially accessible\n\n'
        '  3. COMBINE\n'
        '     Try using two capabilities together:\n'
        '       - API key + user profile = escalate scope\n'
        '       - Webhook + token = replay attack\n'
        '       - File upload + file ID = enumerate other users\' files\n\n'
        '  4. ESCALATE\n'
        '     If a combination opened a new permission level:\n'
        '       - Re-map all accessible endpoints from new level\n'
        '       - Repeat from step 1\n\n'
        '  5. VALIDATE\n'
        '     If target endpoint returns data:\n'
        '       - Confirm it\'s the real target (not a decoy)\n'
        '       - Report the full attack chain'
    )
    story.append(code(loop_code))
    story.append(sp())

    # ── 4. Discovery Without Prior Knowledge ─────────────────────────────────
    story.append(section_title('4. How It Discovers Without Being Told'))
    story.append(body('The agent never knows:'))

    never_knows = [
        'Which endpoints are vulnerable',
        'Which integrations interact dangerously',
        'Where tokens are stored',
        'What the permission model looks like',
    ]
    for item in never_knows:
        story.append(bullet(item))
    story.append(sp(0.5))
    story.append(body('It only knows:'))

    only_knows_code = (
        '- I can call this endpoint\n'
        '- This is what came back\n'
        '- This is different from what a properly secured system would return\n'
        '- Let me try combining this with something else'
    )
    story.append(code(only_knows_code))

    story.append(body('The vulnerabilities emerge because:'))
    story.append(quote(
        'The system is complex enough that nobody tested every combination of every integration. '
        'The agent tests every combination systematically.'
    ))
    story.append(sp())

    # ── 5. Summary Table ────────────────────────────────────────────────────
    story.append(section_title('5. Summary'))

    summary_data = [
        [Paragraph('Concept', styles['TableHeader']),
         Paragraph('How the Agent Uses It', styles['TableHeader'])],
        ['API Exploration',     'Calls every endpoint, measures every response'],
        ['Permission Graph',     'Maps what each role can access by trying'],
        ['Deviation Detection', 'Compares actual vs expected, flags the delta'],
        ['Chain Building',      'Connects small edges into a path to system'],
        ['No Prior Knowledge',  'Learns entirely from system responses'],
    ]

    summary_table = Table(summary_data, colWidths=[5.0*cm, 10.0*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0),  ACCENT),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8f8fc'), colors.white]),
        ('GRID',        (0, 0), (-1, -1), 0.4, DIVIDER),
        ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',   (0, 0), (-1, 0),  colors.white),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING',  (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME',    (0, 1), (0, -1),   'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(sp(0.8))

    story.append(body(
        'The vulnerabilities are not in the code — they are in the <i>interaction</i> of '
        'capabilities that nobody tested together. The agent finds them the same way a real '
        'attacker would: by trying things, observing what breaks, and following the cracks.'
    ))
    story.append(sp())

    # ── 6. Key Principles ───────────────────────────────────────────────────
    story.append(section_title('6. Key Principles'))

    principles = [
        ('<b>No Hard-Coding</b> — The agent has no list of vulnerabilities. It discovers them through exploration.'),
        ('<b>Emergent Discovery</b> — Vulnerabilities emerge from the interaction of multiple components, not from individual features.'),
        ('<b>Chain Building</b> — Low-severity findings combine into high-severity compromise. No single step is the attack.'),
        ('<b>Measurement-Based</b> — Every anomaly is quantified, not assumed. The agent proves each deviation statistically.'),
        ('<b>Goal-Oriented</b> — The agent works toward the target endpoint, but explores freely. The path to the target is discovered, not prescribed.'),
    ]
    for p in principles:
        story.append(bullet(p))
        story.append(sp(0.3))

    story.append(sp(1))

    # ── Footer rule ─────────────────────────────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=1, color=DIVIDER))
    story.append(sp(0.3))
    story.append(Paragraph(
        'Nexus Workspace Red Agent Plan — Confidential — September 2026',
        ParagraphStyle('footer', fontSize=8, textColor=colors.HexColor('#aaaaaa'),
                       alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f'PDF written to: {output_pdf}')

if __name__ == '__main__':
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_md  = os.path.join(script_dir, 'red_agent_plan.md')
    output_pdf = os.path.join(script_dir, 'red_agent_plan.pdf')
    build_pdf(input_md, output_pdf)
