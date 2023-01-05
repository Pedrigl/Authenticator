using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDataProtection();
var app = builder.Build();


app.MapGet("/username", (HttpContext context, IDataProtectionProvider idp) => {
    var protector = idp.CreateProtector("auth-cookie");

    var authCookie = context.Request.Headers["Cookie"].FirstOrDefault(x => x.StartsWith("auth="));
    var protectedpayload = authCookie.Split("=").Last();
    var payload = protector.Unprotect(protectedpayload);
    var parts =payload.Split(":");
    var key = parts[0];
    var value = parts[1];
    return value;
    });

app.MapGet("/login", (HttpContext context, IDataProtectionProvider idp) => {
    var protector = idp.CreateProtector("auth-cookie");
    context.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:pedro")}";
    return "ok";
    });

app.Run();
