from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import print as rprint
import requests
import socket
import whois
import time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

console = Console()

def get_banner():
    banner = """
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃    🌊 WebSea - Website Scanner 🔍   ┃
    ┃      Website Analysis Tool v1.0      ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """
    return Panel(
        Text(banner, style="bold blue", justify="center"),
        border_style="blue",
        padding=(1, 2)
    )

def analyze_website(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    with console.status("[bold blue]Scanning website...", spinner="dots"):
        try:
            domain = url.split('//')[-1].split('/')[0]
            ip = socket.gethostbyname(domain)
            
            w = whois.whois(domain)
            
            response = requests.get(url)
            headers = response.headers
            
            dns_records = {}
            record_types = ['A', 'MX', 'NS', 'TXT', 'AAAA']
            
            for record_type in record_types:
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = records
                except Exception:
                    continue
            
            return {
                'ip': ip,
                'whois': w,
                'headers': headers,
                'dns': dns_records
            }
        except Exception as e:
            return f"Error: {str(e)}"

def format_whois_data(whois_data):
    important_fields = [
        'domain_name', 'registrar', 'creation_date', 
        'expiration_date', 'updated_date', 'name_servers'
    ]
    formatted_data = []
    for field in important_fields:
        if hasattr(whois_data, field) and getattr(whois_data, field):
            value = getattr(whois_data, field)
            if isinstance(value, list):
                value = "\n\t".join(str(v) for v in value)
            formatted_data.append(f"[bold cyan]{field.replace('_', ' ').title()}:[/]\n\t{value}")
    return "\n".join(formatted_data)

def main():
    console.clear()
    console.print(get_banner())
    
    url = console.input("[bold yellow]┏━━━━━━━━━━━━━━━━━━━━\n┃ Enter website URL: [/]")
    
    with Progress(
        "[progress.description]{task.description}",
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.fields[status]}"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            description="[cyan]Scanning...",
            status="Preparing analysis...",
            total=None
        )
        result = analyze_website(url)
    
    if isinstance(result, str):
        console.print(Panel(f"[red]{result}[/]", 
                          title="❌ Error", 
                          border_style="red"))
        return
    
    console.print("\n[bold green]🎯 Analysis Results:[/]\n")
    
    console.print(Panel(
        f"[bold cyan]🌐 Domain:[/] {url}\n[bold cyan]🔍 IP Address:[/] {result['ip']}", 
        title="📌 Basic Information",
        border_style="green",
        padding=(1, 2)
    ))
    
    console.print(Panel(
        format_whois_data(result['whois']),
        title="📋 WHOIS Information",
        border_style="blue",
        padding=(1, 2)
    ))
    
    important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Content-Security-Policy']
    headers_info = "\n".join([
        f"[bold cyan]{k}:[/] {v}" 
        for k, v in result['headers'].items() 
        if k in important_headers or k.startswith('X-')
    ])
    console.print(Panel(
        headers_info,
        title="🔒 HTTP Headers",
        border_style="yellow",
        padding=(1, 2)
    ))
    
    dns_info = []
    for record_type, records in result['dns'].items():
        dns_info.append(f"[bold cyan]{record_type}:[/]")
        for record in records:
            dns_info.append(f"\t{str(record)}")
    
    console.print(Panel(
        "\n".join(dns_info),
        title="🌍 DNS Records",
        border_style="magenta",
        padding=(1, 2)
    ))
    
    console.print("\n[bold green]✅ Scan completed successfully![/]")

if __name__ == "__main__":
    main()