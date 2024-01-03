using LearningFilterPipeline.Filters.AuthorizationFilters;
using Microsoft.AspNetCore.Mvc;

namespace LearningFilterPipeline.Controllers;

[ApiController]
[Route("api/[controller]")]
[ServiceFilter(typeof(PMCBCAuthorizationFilter)) ]
public class PMCBCBaseController
{
    protected readonly IConfiguration configuration;
    public PMCBCBaseController(IConfiguration configuration)
    {
        this.configuration = configuration;
    }
}
