using LearningFilterPipeline.Filters.AuthorizationFilters;
using Microsoft.AspNetCore.Mvc;

namespace LearningFilterPipeline.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [PMCBCAuthorizationFilters]
    public class PMCBCBaseController
    {
    }
}
