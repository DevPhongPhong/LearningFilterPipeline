using LearningFilterPipeline.Filters.AuthorizationFilters;
using LearningFilterPipeline.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LearningFilterPipeline.Controllers;

public class PMCBCFirstController : PMCBCBaseController
{
    public PMCBCFirstController(IConfiguration configuration) : base(configuration)
    {
    }

    [HttpPost]
    [AllowAnonymous]
    public string? Login(Login login)
    {
        if (login.UserName == "a" && login.Password == "a")
        {
            return PMCBCAuthorizationFilterHelpers.GenerateToken(login.UserName,configuration.GetValue<string>("PMCBCAuthorizationConfig:SecretKey"));
        }
        return null;
    }

    [HttpGet]
    public string? GetHihi() { return "hihi"; }
}
