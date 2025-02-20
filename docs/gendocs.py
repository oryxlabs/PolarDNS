import subprocess
import markdown
import tomllib
import random
import glob
import time
import os
import re
from dnslib import DNSRecord
from html import escape

modules_repo_dir = os.path.join('..', 'modules')
catalogue_html_dir = os.path.join('catalogue', 'html')
catalogue_output_dir = os.path.join('catalogue', 'outputs')

modnames = {}
modinfos = {}
modcatgs = {}
modseealso = {}

################################################

def sanitize_filename(text):
    sanitized = "".join(x if x.isalnum() or x in ['.', '_'] else '_' for x in text)
    return sanitized[:250]

################################################

def pcap_explain(pcap_path, pkt):
    cmd = f"tshark -r {pcap_path} -Y dns -T fields -e udp.payload -e tcp.payload"
    result = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE)
    stdout_cleaned = result.stdout.strip()

    lines = stdout_cleaned.splitlines()
    num_lines = len(lines)
    if pkt > num_lines:
        pkt = num_lines
    if pkt < 1:
        pkt = 1

    selected_line = lines[pkt - 1]
    if selected_line.startswith("\t"):
        # TCP starts with a [tab]
        selected_line = selected_line[1:].lstrip()
        selected_line = selected_line[4:]

    output = DNSRecord.parse(bytes.fromhex(selected_line)).toZone()
    tmp = f"<pre class='output-block'>{output}</pre>"
    return tmp

################################################

def transform_text(text, place = ""):
    # Step 1: Escape the text to prevent HTML injection
    tmp = escape(text)

    # Step 2: Define regex patterns and their replacements
    patterns = [
        (r'^\*\*`([^`]*)`\*\*$', r"<pre class='output-block'><strong>\1</strong></pre>", re.MULTILINE),
        (r'`([^`]*)`', r"<code class='code-block'>\1</code>"),
        (r'\[([^<\]]+)\]\(([^\)]+)\)', lambda m: f'<a href="{m.group(2)}" target="_blank">{m.group(1)}</a>')
    ]
    if place == "catalogue":
        patterns.append((r'(?<!\\)\[([^<\]]+)\]', lambda m: f'<a href="../{m.group(1)}/{m.group(1)}.html">{m.group(1)}</a>'))
    else:
        patterns.append((r'(?<!\\)\[([^<\]]+)\]', lambda m: f'<a href="{m.group(1)}.html">{m.group(1)}</a>'))
    patterns.append((r'\\?\[', '['))

    # Step 3: Apply all regex transformations
    for pattern, replacement, *flags in patterns:
        tmp = re.sub(pattern, replacement, tmp, flags=flags[0] if flags else 0)

    # Step 4: Convert the result to Markdown
    tmp = markdown.markdown(tmp)

    # Step 5: Perform any additional symbol replacements
    replacements = {
        ':warning:': '<g-emoji>&#x26A0;</g-emoji>',
        ' - ': ' &mdash; '
    }
    regex = re.compile("|".join(map(re.escape, replacements.keys())))
    return regex.sub(lambda match: replacements[match.group(0)], tmp)

################################################

def format_rfc_links(rfc_string):
    rfc_links = []
    rfc_numbers = re.findall(r'RFC(\d+)', rfc_string, re.IGNORECASE)
    for rfc_number in rfc_numbers:
        link = f'<a href="https://datatracker.ietf.org/doc/rfc{rfc_number}/" target="_blank">RFC{rfc_number}</a>'
        rfc_links.append(link)
    return ', '.join(rfc_links)

################################################

def capitalize_item(item):
    # Match and split known keywords (alias, loop, chain)
    parts = re.split(r'(alias|loop|chain|enum|back|compress|ptr|fuzz|inj|many|bin|txt|new)', item, flags=re.IGNORECASE)
    # Capitalize each part and join them back
    return ''.join(part.capitalize() for part in parts)

################################################

def format_seealso_links(seealso_string, thisitem):
    items = [item.strip() for item in seealso_string.split(',')]
    html_content = "<ul>"
    if thisitem not in modseealso:
        modseealso[thisitem] = {}
    for item in items:
        if item == thisitem or item in modseealso[thisitem]:
            continue
        modseealso[thisitem][item] = 1
        link_text = item.capitalize()
        toml_filename = os.path.join(modules_repo_dir, f"{item}.toml")
        if os.path.isfile(toml_filename):
            try:
                with open(toml_filename, 'rb') as file:
                    data = tomllib.load(file)
                    info = data.get('module', {}).get('info', '')
                    if info:
                        #link_text = f"{item.capitalize()} - {info}"
                        link_text = f"{capitalize_item(item)} - {info}"
            except Exception as e:
                print(f"Error reading {toml_filename}: {e}")

        link = f'<li><a href="{item}.html">{link_text}</a></li>\n'
        html_content += link
    html_content += "</ul>\n"
    return html_content

################################################

def execute_dig(command, pcap_path):
    print(f"Starting tcpdump for the command: {command}")
    iface = 'lo' if "127.0.0.1" in command else 'eth0'
    # sometimes the packet is fragmented and it does not get captured with port 53 filter
    #tcpdump_command = ['sudo', 'tcpdump', '-i', iface, '-s', '0', '-n', '-w', pcap_path, 'port 53']
    tcpdump_command = ['sudo', 'tcpdump', '-i', iface, '-s', '0', '-n', '-w', pcap_path]
    tcpdump_process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.5)

    output = ""
    commands = command.split(";")

    try:
        for cmd in commands:
            cmd = cmd.strip()  # Remove any leading/trailing whitespace
            realcmd = cmd
            if '${RANDOM}' in cmd:
                # Replace '${RANDOM}' with a random number
                random_number = random.randint(0, 32767)
                realcmd = cmd.replace('${RANDOM}', str(random_number))
            if cmd.startswith("dig "):
                result = subprocess.run(realcmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_cleaned = result.stdout.strip()
                stderr_cleaned = result.stderr.strip()
                if " +short;" in command:
                    output += f"<strong># {cmd}</strong>  --&gt;  {escape(stdout_cleaned)}\n"
                else:
                    output += f"<strong># {cmd}</strong>\n\n{escape(stdout_cleaned)}\n{escape(stderr_cleaned)}\n\n"
            else:
                output += f"<strong># {cmd}</strong>\n\nUnexpected command\n\n"
    except Exception as e:
        output += f"<strong># {command}</strong>\n\nError: {escape(str(e))}\n\n"
    
    time.sleep(0.5)
    tcpdump_process.terminate()
    time.sleep(0.2)
    if tcpdump_process.poll() is None:
        tcpdump_process.kill()
    tcpdump_process.wait()
    print("Stopped tcpdump.")
    
    return output.strip()  # Remove any trailing newlines

################################################

def categorize(file_path):
    #print(f"Categorizing module: {file_path}")
    try:
        with open(file_path, 'rb') as file:
            data = tomllib.load(file)
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return
    except tomllib.TOMLDecodeError as e:
        print(f"Error decoding TOML: {e}")
        return

    module_data = data.get('module', {})
    module_file = os.path.basename(file_path)[:-5]
    if 'category' in module_data:
        module_catg = escape(module_data.get('category', ''))
        if module_catg.strip():
           modcatgs.setdefault(module_catg, []).append(module_file)
    else:
        print(f"Error: The module {file_path} has no category.")
        return

################################################

def generate_module_page(file_path):
    print(f"Generating HTML page for module: {file_path}")
    try:
        with open(file_path, 'rb') as file:
            data = tomllib.load(file)
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return
    except tomllib.TOMLDecodeError as e:
        print(f"Error decoding TOML: {e}")
        return

    module_data = data.get('module', {})
    module_file = os.path.basename(file_path)[:-5]
    module_link = os.path.join(module_file, module_file + '.html')

    # # # # # # # # # # # # # # # # # # # # #

    module_name = module_data.get('name', '')
    module_info = module_data.get('info', '')
    module_type = module_data.get('type', '')
    module_short = module_data.get('short', '')
    module_catg = module_data.get('category', '')

    module_description = module_data.get('desc', 'No description available.')
    module_description = transform_text(module_description)

    # # # # # # # # # # # # # # # # # # # # #
    # check for duplicates

    if module_name in modnames:
        print(f"WARN: Duplicate module name {module_name}")
    else:
        modnames[module_name] = 1

    if module_info in modinfos:
        print(f"WARN: Duplicate module info {module_info}")
    else:
        modinfos[module_info] = 1

    # # # # # # # # # # # # # # # # # # # # #

    title_and_header = f"{capitalize_item(module_name)} - {module_info}"

    module_output_dir = os.path.join(catalogue_output_dir, module_file)
    os.makedirs(module_output_dir, exist_ok=True)

    html_output = f"""---
layout: default
title: "{title_and_header}"
parent: "{module_catg}"
---

<!DOCTYPE html>
<head>
<title>{title_and_header}</title>
<link rel="stylesheet" type="text/css" href="../style.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown.min.css">
</head>
<body>
<h1>{title_and_header}</h1>
"""
    html_output += f"{module_description}"

    module_catg = escape(module_data.get('category', ''))
    if module_catg.strip():
        catg_link = "../" + module_catg.lower().replace(" ", "-") + ".html"
        html_output += f"<p><strong>Category:</strong> <a href='{catg_link}'>{module_catg}</a></p>"

    module_tags = escape(module_data.get('tags', ''))
    if module_tags.strip():
        html_output += f"<p><strong>Tags:</strong> {module_tags}</p>"

    module_rfcs = module_data.get('rfc', '')
    if module_rfcs.strip():
       module_rfcs = format_rfc_links(module_rfcs)
       html_output += f"<p><strong>RFCs:</strong> {module_rfcs}</p>"

    if 'format' in module_data:
        html_output += "\n<h2>Format</h2>\n"
        module_format = module_data.get('format', 'No format available.')
        module_format = transform_text(module_format)
        html_output += f"{module_format}"
    
    if 'example' in module_data:
        html_output += "\n<h2>Examples</h2>\n"
        for example in module_data['example']:
            command = example['command']
            try:
                description = transform_text(example['description'])
            except:
                description = ""
            try:
                pcapexplain = transform_text(example['pcapexplain'])
            except:
                pcapexplain = ""
            try:
                postdescription = transform_text(example['append'])
            except:
                postdescription = ""

            command_filename = sanitize_filename(command)
            pcap_path = os.path.join(module_output_dir, command_filename + '.pcap')
            filepath = os.path.join(module_output_dir, command_filename + '.html')
            rel_pcap_path = os.path.join('..', 'outputs', module_file, command_filename + '.pcap')
            if description:
                html_output += f"{description}"
            if not os.path.exists(filepath):
                output = execute_dig(command, pcap_path)
                tmp = f"<pre class='output-block'>{output}</pre>"
                tmp = re.sub(r'([^>])(warning)', r'\1<span style="background-color: yellow;">\2</span>', tmp, flags=re.IGNORECASE)
                tmp = re.sub(r'([^a-z>])(error)', r'\1<span style="background-color: yellow;">\2</span>', tmp, flags=re.IGNORECASE)
                tmp = re.sub(r'([^a-z>])(Got bad packet)', r'\1<span style="background-color: yellow;">\2</span>', tmp, flags=re.IGNORECASE)
                tmp = re.sub(r'([^a-z>])(Question section mismatch)', r'\1<span style="background-color: yellow;">\2</span>', tmp, flags=re.IGNORECASE)
                tmp = re.sub(r'(;; Query time: )(\d+ msec)', lambda match: f'{match.group(1)}<span style="background-color: yellow;">{match.group(2)}</span>' if int(match.group(2).split()[0]) > 1000 else match.group(0), tmp)
                #if "dig inj" in command:
                if "dig " in command and " inj" in command:
                    # special formatting for injection scenarios
                    tmp = re.sub(r"^;?injected.*6\.6\.6\..*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    tmp = re.sub(r"^;?injected.*6666:6666:6666.*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    tmp = re.sub(r"^;?6\.6\.6\..*injected.*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    tmp = re.sub(r"^;?injected.*always.*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    tmp = re.sub(r'(NXDOMAIN)', r'<span style="color:red;">\1</span>', tmp)
                with open(filepath, 'w') as file:
                    file.write(tmp)
            with open(filepath, 'r') as file:
                html_output += f"\n<div>{file.read()}</div>"
                if pcapexplain:
                    html_output += f"{pcapexplain}"
                    tmp = pcap_explain(pcap_path, 2)
                    tmp = re.sub(r"(?<!\n)\n(;; QUESTION SECTION:)", r"\n\n\1", tmp)
                    tmp = re.sub(r"(?<!\n)\n(;; ANSWER SECTION:)", r"\n\n\1", tmp)
                    tmp = re.sub(r"(?<!\n)\n(;; AUTHORITY SECTION:)", r"\n\n\1", tmp)
                    tmp = re.sub(r"(?<!\n)\n(;; ADDITIONAL SECTION:)", r"\n\n\1", tmp)
                    tmp = re.sub(r"^;?injected.*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    tmp = re.sub(r"^;?6\.6\.6\..*injected.*$", r'<span style="color:red;">\g<0></span>', tmp, flags=re.MULTILINE)
                    html_output += tmp
                html_output += f"<p><a href='{rel_pcap_path}'>Download PCAP File</a></p>"
                if postdescription:
                    html_output += f"<p>{postdescription}</p>"
                html_output += f"<br>\n"

    if modcatgs[module_catg]:
        value = ','.join(modcatgs[module_catg])
        value = format_seealso_links(value, module_file)
        if value.strip() != '<ul></ul>':
            html_output += "\n<h2>From the same category</h2>\n"
            html_output += f"{value}"

    if 'seealso' in module_data:
        value = module_data['seealso']
        value = format_seealso_links(value, module_file)
        if value.strip() != '<ul></ul>':
            html_output += "\n<h2>See also</h2>\n"
            html_output += f"{value}"

    html_output += f"<br><p>Go <strong><u><a href='../catalogue.html'>back to catalogue</a></strong></u>.</p>"

    html_output += "\n</body>\n</html>"

    output_html_file = os.path.join(catalogue_html_dir, module_file + '.html')
    os.makedirs(catalogue_html_dir, exist_ok=True)

    with open(output_html_file, "w") as file:
        file.write(html_output)


################################################

def catalogue_process_module(file_path):
    print(f"Adding to catalogue: {file_path}")
    try:
        with open(file_path, 'rb') as file:
            data = tomllib.load(file)
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return
    except tomllib.TOMLDecodeError as e:
        print(f"Error decoding TOML: {e}")
        return

    module_file = os.path.basename(file_path)[:-5]
    #module_link = os.path.join(module_file, module_file + '.html')
    #module_link = module_file + '.html'
    module_link = os.path.join('html', module_file + '.html')
    module_data = data.get('module', {})
    module_name = module_data.get('name', '')
    module_type = module_data.get('type', '')
    module_info = module_data.get('info', '').title()
    module_short = module_data.get('short', '')
    module_catg = module_data.get('category', '')
    module_tags = module_data.get('tags', '')

    #module_rfcs = module_data.get('rfc', '')
    #module_rfcs = format_rfc_links(module_rfcs)

    module_description = module_data.get('desc', 'No description available.')
    module_description = transform_text(module_description, "catalogue")

    output = f"""      <tr>
        <td class="name"><a href="{module_link}"><strong>{module_name}</strong></a></td>
        <td class="type">{module_type}</td>
        <td class="info">{module_short}</td>
        <td class="catg">{module_catg}</td>
        <td class="tags">{module_tags}</td>
      </tr>"""
    return output

################################################
# main()

################################################
# 1) generate html page for each module

print("Generating module HTML pages")

toml_files = glob.glob(os.path.join(modules_repo_dir, '*.toml'))
toml_files = sorted(toml_files)

for file_path in toml_files:
    categorize(file_path)

for file_path in toml_files:
    generate_module_page(file_path)

################################################
# 2) generate catalogue html page

print("Generating catalogue")

title_and_header = "PolarDNS Catalogue"
html_output = f"""---
layout: default
title: Catalogue
nav_order: 10
has_children: true
has_toc: false
---

<!DOCTYPE html>
<head>
<title>{title_and_header}</title>
<link rel="stylesheet" type="text/css" href="../style.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.1.0/github-markdown.min.css">
</head>
<body>
<h1>{title_and_header}</h1>

<p>This is PolarDNS catalogue:</p>

<div id="catalogue">
  <input class="search" placeholder="Search"/>
  <table>
    <thead>
      <tr>
        <th><button class="sort" data-sort="name">Name</button></th>
        <th><button class="sort" data-sort="type">Type</button></th>
        <th><button class="sort" data-sort="info">Info</button></th>
        <th><button class="sort" data-sort="catg">Category</button></th>
        <th><button class="sort" data-sort="tags">Tags</button></th>
      </tr>
    </thead>
    <!-- IMPORTANT, class="list" have to be at tbody -->
    <tbody class="list">
"""

for file_path in toml_files:
    html_output += catalogue_process_module(file_path)

html_output += """
    </tbody>
  </table>

<script src="https://cdnjs.cloudflare.com/ajax/libs/list.js/2.3.1/list.min.js"></script>
<script>
var options = {
  valueNames: [ 'name', 'type', 'info', 'catg', 'tags' ]
};

var modList = new List('catalogue', options);
</script>

</div>
</body>
</html>
"""

os.makedirs('catalogue', exist_ok=True)
output_index_path = os.path.join('catalogue', 'catalogue.html')

with open(output_index_path, "w") as file:
    file.write(html_output)

################################################
print("All done")
