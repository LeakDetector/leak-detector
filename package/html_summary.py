import json
import pprint
from flask import Flask, render_template

app = Flask(__name__)
app.config.update(
    session=json.load(open("/Users/nhfruchter/Dropbox/Leak Detector Summer 2014/Example output/oct19-2014.analyzed.json"))
)

@app.route('/')
def report():
    return render_template("report-template.jinja2", title="Test", report=app.config['session'])
    
def dict2table(p, htmlclass):
    out = []
    out.append("<table class='%s'>" % htmlclass)
    for key, value in p.iteritems():
        if value and key != "__VIEWSTATE" and len(value[0]) < 400:
            out.append("<tr><td>%s</td><td>%s</td></tr>" % (key, value))
    out.append("</table>")
    return out

def handle_display(attribute, item):    
    def domains(item):
        domains = [".".join(domain) for domain in item]
        return "\n".join(["<span class='attached-domain'>%s</span>" % d for d in domains])
        
    def products(item):
        out = []
        for p in item:
            if p: out += dict2table(p, "product")
        return "\n".join(out)
        
    def queries(item):
        return "\n".join(["<span class='query'>%s</span>" % d for d in item])
                
    def category(item):
        if type(item) in (list, tuple):
            return " > ".join(item)
        else:
            return item    
            
    def formdata(item):
        out = []
        for chunk in item:
            domain, page, data = chunk
            out.append("<div class=\"form\">")
            out.append("<h5>Data submitted to %s</h5>" % page)
            out += dict2table(data, "formdata")
            out.append("</div>")
        return "\n".join(out)
        
    def email(item): return item[-1]
        
    def personal_email(item):
        return email(item)
        
        
    try:
        return locals()[attribute.replace("-","_")](item)
    except KeyError:
        return item    
    
app.jinja_env.globals.update(pp=handle_display)

if __name__ == '__main__':
    app.run(debug=True)
    
