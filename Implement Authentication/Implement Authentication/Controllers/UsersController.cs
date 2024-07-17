using Implement_Authentication.Modles;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FirstAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {

        public UsersController(UserManager<AppUser> userManager, IConfiguration configuration)
        {
            UserManager=userManager;
            Configuration=configuration;
        }

        public UserManager<AppUser> UserManager { get; }
        public IConfiguration Configuration { get; }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(Register regUser)
        {
            if (ModelState.IsValid)
            {
                AppUser appUser = new()
                {
                    UserName = regUser.userName,
                    Email = regUser.email

                };

                IdentityResult result = await UserManager.CreateAsync(appUser, regUser.password);

                if (result.Succeeded)
                {
                    return Ok("Success");
                }

                else
                {
                    foreach (var iten in result.Errors)
                    {
                        ModelState.AddModelError("", iten.Description);
                    }
                }

            }
            return BadRequest();
        }


        [HttpPost("Loging")]
        public async Task<IActionResult> Login(Login lohinUser)
        {
            if (ModelState.IsValid)
            {
                AppUser? user = await UserManager.FindByNameAsync(lohinUser.userName);
                if (user != null)
                {
                    if (await UserManager.CheckPasswordAsync(user, lohinUser.password))
                    {
                        var clamis = new List<Claim>();
                        clamis.Add(new Claim(ClaimTypes.Name, user.UserName));
                        clamis.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
                        clamis.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

                        var roles = await UserManager.GetRolesAsync(user);
                        foreach (var role in roles)
                        {
                            clamis.Add(new Claim(ClaimTypes.Role, role.ToString()));
                        }

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SigningKey"]));
                        var sc = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var token = new JwtSecurityToken(

                            claims: clamis,
                            signingCredentials: sc,
                            audience: Configuration["Jwt:Audience"],
                            expires: DateTime.Now.AddHours(1),
                            issuer: Configuration["Jwt:Issuer"]

                            );

                        var _token = new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        };

                        return Ok(_token);
                    }

                    else
                    {
                        return Unauthorized();
                    }
                }

                else
                {
                    ModelState.AddModelError("", "Error");
                }

            }

            return BadRequest(ModelState);
        }


    }
}
