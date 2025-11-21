using CleanFluentEF.Models.DomainModels.ProductAggregates;
using CleanFluentEF.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CleanFluentEF.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public ProductsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // -----------------------------
        // GET: api/Products
        // -----------------------------
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Product>>> GetProducts()
        {
            return await _context.Set<Product>()
                                 .Include(p => p.Category) // Load Category navigation
                                 .ToListAsync();
        }

        // -----------------------------
        // GET: api/Products/{id}
        // -----------------------------
        [HttpGet("{id}")]
        public async Task<ActionResult<Product>> GetProduct(Guid id)
        {
            var product = await _context.Set<Product>()
                                        .Include(p => p.Category)
                                        .FirstOrDefaultAsync(p => p.Id == id);

            if (product == null) return NotFound();

            return product;
        }

        // -----------------------------
        // POST: api/Products
        // -----------------------------
        [HttpPost]
        public async Task<ActionResult<Product>> CreateProduct(Product product)
        {
            product.Id = Guid.NewGuid();
            product.DateCreation = DateTime.UtcNow;
            product.DateModification = DateTime.UtcNow;

            _context.Set<Product>().Add(product);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetProduct), new { id = product.Id }, product);
        }

        // -----------------------------
        // PUT: api/Products/{id}
        // -----------------------------
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateProduct(Guid id, Product product)
        {
            if (id != product.Id) return BadRequest();

            product.DateModification = DateTime.UtcNow;

            _context.Entry(product).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await _context.Set<Product>().AnyAsync(p => p.Id == id))
                    return NotFound();
                throw;
            }

            return NoContent();
        }

        // -----------------------------
        // DELETE: api/Products/{id}
        // -----------------------------
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteProduct(Guid id)
        {
            var product = await _context.Set<Product>().FindAsync(id);
            if (product == null) return NotFound();

            _context.Set<Product>().Remove(product);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
