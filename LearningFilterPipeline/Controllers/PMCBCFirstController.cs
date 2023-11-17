using LearningFilterPipeline.Commons;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LearningFilterPipeline.Controllers
{
    public class PMCBCFirstController:PMCBCBaseController
    {
        public PMCBCFirstController() { }

        [HttpGet]
        public string Get()
        {
            return "Hello";
        }

        [HttpPost]
        [AllowAnonymous]
        public string? Login(string username, string password)
        {
            if (username == CommonConstants.Username && password == CommonConstants.Password)
            {
                return CommonFunctions.GenerateToken(CommonConstants.Id);
            }
            return null;
        }
    }
}
