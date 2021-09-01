using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }
        [HttpGet]
        public IActionResult Login(string userName, string password)
        {
            UserModel login = new UserModel();
            login.UserName = userName;
            login.Password = password;
            IActionResult response = Unauthorized();

            var user = AuthenticateUser(login);

            if (user != null)
            {
                var tokenStr = GenerateJsonWebToken(user);
                response = Ok(new { token = tokenStr });
            }

            return response;
        }

        private string GenerateJsonWebToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Email,user.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(2),
                signingCredentials: credentials

                );

            var encodeToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodeToken;
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;
            //Demo use static Info
            if (login.UserName == "haodeptrai" && login.Password == "123456")
            {
                user = new UserModel()
                {
                    UserName = "HaoDepTrai",
                    EmailAddress = "nguyendinhhao.iuh@gmail.com",
                    Password = "123456"
                };
            }
            return user;
        }

        [Authorize]
        [HttpPost("Post")]
        public string Post()
        {
            var identiy = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claims = identiy.Claims.ToList();
            var userName = claims[0].Value;

            return $"Welcome to {userName}";
        }

        [Authorize]
        [HttpGet("GetValue")]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "Value1","Value2","Value3"};
        }
    }
}
