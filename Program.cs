using Microsoft.AspNetCore.DataProtection;
using System.Runtime.Intrinsics.Arm;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDataProtection();
builder.Services.AddScoped<AuthService>();
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

app.MapGet("/login", (AuthService auth) => {
    auth.SignIn();
    });

app.Run();

public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly HttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider idp, HttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }
    
    public Task SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");
        _accessor.HttpContext.Headers["set-cookie"] = $"auth={protector.Protect("usr:pedro")}";
    }
}
