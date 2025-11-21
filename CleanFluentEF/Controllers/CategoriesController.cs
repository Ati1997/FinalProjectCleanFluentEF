using CleanFluentEF.Models.DomainModels.ProductAggregates;
using CleanFluentEF.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CleanFluentEF.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CategoriesController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public CategoriesController(ApplicationDbContext context)
        {
            _context = context;
        }

        // -----------------------------
        // GET: api/Categories
        // -----------------------------
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Category>>> GetCategories()
        {
            return await _context.Set<Category>()
                                 .Include(c => c.Products) // Include related Products
                                 .ToListAsync();
        }

        // -----------------------------
        // GET: api/Categories/{id}
        // -----------------------------
        [HttpGet("{id}")]
        public async Task<ActionResult<Category>> GetCategory(Guid id)
        {
            var category = await _context.Set<Category>()
                                         .Include(c => c.Products)
                                         .FirstOrDefaultAsync(c => c.Id == id);

            if (category == null) return NotFound();

            return category;
        }

        // -----------------------------
        // POST: api/Categories
        // -----------------------------
        [HttpPost]
        public async Task<ActionResult<Category>> CreateCategory(Category category)
        {
            category.Id = Guid.NewGuid();
            _context.Set<Category>().Add(category);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetCategory), new { id = category.Id }, category);
        }

        // -----------------------------
        // PUT: api/Categories/{id}
        // -----------------------------
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateCategory(Guid id, Category category)
        {
            if (id != category.Id) return BadRequest();

            _context.Entry(category).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await _context.Set<Category>().AnyAsync(c => c.Id == id))
                    return NotFound();
                throw;
            }

            return NoContent();
        }

        // -----------------------------
        // DELETE: api/Categories/{id}
        // -----------------------------
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteCategory(Guid id)
        {
            var category = await _context.Set<Category>().FindAsync(id);
            if (category == null) return NotFound();

            _context.Set<Category>().Remove(category);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
